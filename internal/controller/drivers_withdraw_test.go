package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/craftainer-labs/lib-operator-go/pkg/dcr"

	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

var errBoom = errors.New("boom")

// isState says the Secret is a registration state.
func isState(obj client.Object) bool {
	s, ok := obj.(*corev1.Secret)
	return ok && strings.HasPrefix(s.Name, "dcr-")
}

// freshDCR is the driver of a claim that has made nothing, on a provider that
// registers clients, and the spec it wants.
func freshDCR(t *testing.T, f *dcrFake, funcs interceptor.Funcs) (*oc, *dcrDriver, clientSpec) {
	t.Helper()
	o := dcrOC(t, f, funcs)
	c := o.get()
	d := o.driver(c).(*dcrDriver)
	w, err := resolveSpec(c.Spec, allowedScopes)
	if err != nil {
		t.Fatal(err)
	}
	return o, d, w
}

func (f *dcrFake) has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.clients[id]
	return ok
}

// A registration the status cannot record is withdrawn even when the
// reconcile's context is cancelled: the compensating calls use their own.
func TestDCRWithdrawsOnACancelledContext(t *testing.T) {
	f := startDCR(t)
	o, d, w := freshDCR(t, f, interceptor.Funcs{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.persist = func(ctx context.Context) error { cancel(); return ctx.Err() }
	if _, err := d.create(ctx, w); err == nil {
		t.Fatal("a failing status write was ignored")
	}
	if f.has("dcr-1") || o.secret(opsNS, dcr.SecretName("uid-web")) != nil || d.claim.GetExternalID() != "" {
		t.Error("the registration or its state was left")
	}
	if cond(d.claim, conditionRegistrationUnconfirmed) != nil {
		t.Error("a withdrawn registration is no risk")
	}
}

// A registration whose state cannot be stored is withdrawn on a cancelled
// context too.
func TestDCRStoreFailureOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := startDCR(t)
	_, d, w := freshDCR(t, f, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if isState(obj) {
			cancel()
			return errBoom
		}
		return c.Create(ctx, obj, opts...)
	}})
	if _, err := d.register(ctx, w); err == nil {
		t.Fatal("a registration that cannot be stored was accepted")
	}
	if f.has("dcr-1") {
		t.Error("the registration was left at the provider")
	}
}

// A registration the provider no longer knows is gone as far as the operator
// can tell: register and withdraw both treat it so, and neither is a risk.
func TestDCRCompensationToleratesALostRegistration(t *testing.T) {
	f := startDCR(t)
	f.with(func() { f.fail["DELETE /register/dcr-1"] = 401 })
	o, d, w := freshDCR(t, f, interceptor.Funcs{})
	d.persist = func(context.Context) error { return errBoom }
	if _, err := d.create(context.Background(), w); err == nil {
		t.Fatal("a failing status write was ignored")
	}
	if cond(d.claim, conditionRegistrationUnconfirmed) != nil || o.secret(opsNS, dcr.SecretName("uid-web")) != nil {
		t.Error("a lost registration was a risk, or its state was kept")
	}

	f = startDCR(t)
	f.with(func() { f.fail["DELETE /register/dcr-1"] = 401 })
	_, d, w = freshDCR(t, f, interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if isState(obj) {
			return errBoom
		}
		return c.Create(ctx, obj, opts...)
	}})
	if _, err := d.register(context.Background(), w); err == nil {
		t.Fatal("a registration that cannot be stored was accepted")
	}
	if cond(d.claim, conditionRegistrationUnconfirmed) != nil {
		t.Error("a lost registration was a risk")
	}
}

// A withdrawal that cannot delete the registration keeps its state and the
// claim's client_id, and reports an orphan risk with an Event: the registration
// stays accounted for, and the next observe manages it.
func TestDCRWithdrawThatCannotDeleteIsRetried(t *testing.T) {
	f := startDCR(t)
	f.with(func() { f.fail["DELETE /register/dcr-1"] = 500 })
	o, d, w := freshDCR(t, f, interceptor.Funcs{})
	d.persist = func(context.Context) error { return errBoom }
	if _, err := d.create(context.Background(), w); err == nil {
		t.Fatal("a failing status write was ignored")
	}
	wantCond(t, d.claim, conditionRegistrationUnconfirmed, metav1.ConditionTrue, reasonCleanupFailed)
	if !o.rec.has("Warning " + reasonCleanupFailed) {
		t.Errorf("events = %v", o.rec.events)
	}
	if o.secret(opsNS, dcr.SecretName("uid-web")) == nil {
		t.Fatal("the state of a registration that is still there was dropped")
	}
	obs, err := d.observe(context.Background(), w, nil)
	if err != nil || !obs.Exists || obs.Current.reg.ClientID != "dcr-1" {
		t.Fatalf("observe = %+v, %v", obs, err)
	}
	if d.claim.GetExternalID() != "dcr-1" {
		t.Error("the registration is not recorded")
	}
}

// A withdrawal whose state cannot be deleted is reported, and the next observe
// removes the state of a registration that is gone, instead of holding the claim
// in a lost registration it never recorded.
func TestDCRWithdrawThatCannotDeleteTheState(t *testing.T) {
	failing := true
	f := startDCR(t)
	o, d, w := freshDCR(t, f, interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
		if isState(obj) && failing {
			return errBoom
		}
		return c.Delete(ctx, obj, opts...)
	}})
	d.persist = func(context.Context) error { return errBoom }
	if _, err := d.create(context.Background(), w); err == nil {
		t.Fatal("a failing status write was ignored")
	}
	wantCond(t, d.claim, conditionRegistrationUnconfirmed, metav1.ConditionTrue, reasonCleanupFailed)
	if f.has("dcr-1") || d.claim.GetExternalID() != "" || o.secret(opsNS, dcr.SecretName("uid-web")) == nil {
		t.Fatal("the registration was left, or the state went")
	}
	failing = false
	obs, err := d.observe(context.Background(), w, nil)
	if err != nil || obs.Exists {
		t.Fatalf("observe = %+v, %v", obs, err)
	}
	if o.secret(opsNS, dcr.SecretName("uid-web")) != nil {
		t.Error("the stale state was kept")
	}
}

// A state that cannot be removed with a lost registration is an error, not a
// silent success.
func TestDCRObserveOfAStaleStateThatCannotBeDeleted(t *testing.T) {
	f := startDCR(t)
	o, d, w := freshDCR(t, f, interceptor.Funcs{Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
		return errBoom
	}})
	if _, err := d.register(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	d.claim.SetExternalID("")
	f.with(func() { delete(f.clients, "dcr-1") })
	if _, err := d.observe(context.Background(), w, nil); err == nil {
		t.Error("a stale state that stayed was not reported")
	}
	if o.secret(opsNS, dcr.SecretName("uid-web")) == nil {
		t.Error("the state went")
	}
}

// A rotation whose status cannot be written takes the new registration back and
// restores the old one's state, so the claim still manages the registration its
// status names.
func TestDCRRotationRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name          string
		failNewDelete bool
		failRestore   bool
		risk          bool
	}{
		{name: "clean"},
		{name: "the new one cannot be deleted", failNewDelete: true, risk: true},
		{name: "the old state cannot be restored", failRestore: true, risk: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failUpdate := false
			f := startDCR(t)
			o := dcrOC(t, f, interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if isState(obj) && failUpdate {
					return errBoom
				}
				return c.Update(ctx, obj, opts...)
			}})
			o.ok()
			old := stateOf(t, o)
			c := o.get()
			d := o.driver(c).(*dcrDriver)
			w, _ := resolveSpec(c.Spec, allowedScopes)
			if tc.failNewDelete {
				f.with(func() { f.fail["DELETE /register/dcr-2"] = 500 })
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d.persist = func(context.Context) error {
				failUpdate = tc.failRestore
				cancel()
				return errBoom
			}
			if _, err := d.rotateBegin(ctx, w, clientState{reg: old}); err == nil {
				t.Fatal("a failing status write was ignored")
			}
			if f.saw("DELETE /register/dcr-1") || !f.has("dcr-1") {
				t.Error("the old registration was touched")
			}
			if f.has("dcr-2") != tc.failNewDelete {
				t.Errorf("the new registration present = %v", f.has("dcr-2"))
			}
			if (cond(d.claim, conditionRegistrationUnconfirmed) != nil) != tc.risk || o.rec.has("Warning "+reasonCleanupFailed) != tc.risk {
				t.Errorf("risk = %v, events = %v", cond(d.claim, conditionRegistrationUnconfirmed), o.rec.events)
			}
			if d.claim.GetExternalID() != "dcr-1" {
				t.Errorf("the claim records %q", d.claim.GetExternalID())
			}
			if !tc.failRestore {
				if got := stateOf(t, o); got != old {
					t.Errorf("the old state was not restored: %v", got)
				}
			}
		})
	}
}

// A condition about a client that could not be taken back stays when a later
// registration works; one about an unexpected answer is cleared by it.
func TestDCRGoodRegistrationClearsOnlyTheRiskOfAnAnswer(t *testing.T) {
	f := startDCR(t)
	_, d, w := freshDCR(t, f, interceptor.Funcs{})
	d.orphanRisk(reasonCleanupFailed)
	if _, err := d.register(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	if cond(d.claim, conditionRegistrationUnconfirmed) == nil {
		t.Error("a risk about a client that stayed was cleared")
	}
	d.orphanRisk(reasonRegistrationUnconfirmed)
	if _, err := d.register(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	if cond(d.claim, conditionRegistrationUnconfirmed) != nil {
		t.Error("a risk about an answer stayed after a good registration")
	}
}

// A Keycloak client the status cannot record is deleted on a cancelled context
// too; one that cannot be deleted is an orphan risk with an Event, and stays
// recorded in the claim; the retry adopts it by its marker.
func TestKeycloakCreateCompensation(t *testing.T) {
	f := startIDP(t)
	o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient())...)
	c := o.get()
	d := o.driver(c).(*keycloakDriver)
	w, _ := resolveSpec(c.Spec, allowedScopes)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.persist = func(context.Context) error { cancel(); return errBoom }
	if _, err := d.create(ctx, w); err == nil {
		t.Fatal("a failing status write was ignored")
	}
	if !f.kc.saw("DELETE /clients/kc-1") || d.claim.GetExternalID() != "" || cond(d.claim, conditionRegistrationUnconfirmed) != nil {
		t.Error("the client was not taken back")
	}

	f.kc.failing("DELETE /clients/kc-2", 500)
	if _, err := d.create(context.Background(), w); err == nil {
		t.Fatal("a failing status write was ignored")
	}
	wantCond(t, d.claim, conditionRegistrationUnconfirmed, metav1.ConditionTrue, reasonCleanupFailed)
	if !o.rec.has("Warning "+reasonCleanupFailed) || d.claim.GetExternalID() != "kc-2" {
		t.Errorf("events = %v, id = %q", o.rec.events, d.claim.GetExternalID())
	}
	f.kc.failing("DELETE /clients/kc-2", 0)
	d.persist = func(context.Context) error { return nil }
	if _, err := d.create(context.Background(), w); err != nil {
		t.Fatalf("the retry = %v", err)
	}
	if d.claim.GetExternalID() != "kc-2" {
		t.Errorf("the retry did not adopt the client: %q", d.claim.GetExternalID())
	}
}

// takeBack treats a client or registration the provider does not know as gone.
func TestClientGone(t *testing.T) {
	if !clientGone(idpclient.ErrNotFound) || !clientGone(idpclient.ErrRegistrationLost) || clientGone(errBoom) {
		t.Error("clientGone")
	}
}
