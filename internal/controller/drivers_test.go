package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/dcr"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// moreRedirect adds a redirect URI to the claim, which a provider's answer
// carries back and so counts as a difference.
func moreRedirect(uri string) func(*oidcv1alpha1.OidcClient) {
	return func(c *oidcv1alpha1.OidcClient) {
		c.Spec.RedirectURIs = append(c.Spec.RedirectURIs, oidcv1alpha1.RedirectURI(uri))
	}
}

// dcrOC is a reconciler on a provider that registers clients.
func dcrOC(t *testing.T, f *dcrFake, funcs interceptor.Funcs, mut ...func(*oidcv1alpha1.OidcClient)) *oc {
	t.Helper()
	return newOC(t, funcs, with(dcrObjects(f), oidcClient(append([]func(*oidcv1alpha1.OidcClient){func(c *oidcv1alpha1.OidcClient) {
		c.Spec.ServerRef = ref(kindIdentityProvider, "dcr")
	}}, mut...)...))...)
}

func stateOf(t *testing.T, o *oc) dcr.State {
	t.Helper()
	s := o.secret(opsNS, dcr.SecretName("uid-web"))
	if s == nil {
		t.Fatal("no registration state")
	}
	return dcr.State{
		ClientID: string(s.Data[dcr.KeyClientID]), RegistrationClientURI: string(s.Data[dcr.KeyRegistrationClientURI]),
		RegistrationAccessToken: string(s.Data[dcr.KeyRegistrationToken]),
	}
}

// A dynamically registered client is registered once, its registration is kept
// in a Secret of the operator namespace and re-stored when the provider issues
// a new token, it is updated only when it differs, re-registered to rotate
// and deleted with its claim.
func TestDCRClientLifecycle(t *testing.T) {
	f := startDCR(t)
	o := dcrOC(t, f, interceptor.Funcs{})

	o.ok()
	c := o.get()
	wantCond(t, c, conditions.Ready, metav1.ConditionTrue, "")
	st := stateOf(t, o)
	if c.Status.ExternalID != "dcr-1" || st.ClientID != "dcr-1" || st.RegistrationAccessToken != "rat-1" ||
		c.Status.RegistrationClientURI != f.srv.URL+"/register/dcr-1" || st.RegistrationClientURI != c.Status.RegistrationClientURI {
		t.Fatalf("status = %+v, state = %v", c.Status, st)
	}
	b := o.secret("team", "web")
	if string(b.Data["clientId"]) != "dcr-1" || string(b.Data["clientSecret"]) != "dcr-secret-1" {
		t.Errorf("binding = %v", b.Data)
	}
	// Credentials are in Secrets only: never in the status.
	status, _ := json.Marshal(c.Status)
	for _, secret := range []string{"rat-1", "dcr-secret-1"} {
		if strings.Contains(string(status), secret) {
			t.Errorf("%s reached the status", secret)
		}
	}
	if s := o.secret(opsNS, dcr.SecretName("uid-web")); s.Labels["app.kubernetes.io/managed-by"] != "operator-oidc" {
		t.Errorf("state labels = %v", s.Labels)
	}

	// Nothing differs: nothing is written.
	o.ok()
	if f.saw("PUT /register/dcr-1") {
		t.Fatal("a matching registration was updated")
	}

	// A changed spec is a PUT, and the new token the provider answers with is
	// stored: the next read has to use it.
	f.with(func() { f.newToken = true })
	o.edit(moreRedirect("https://app.example/other"))
	o.ok()
	// The read before the update and the update itself each brought a token.
	if got := stateOf(t, o).RegistrationAccessToken; got != "rat-1++" {
		t.Fatalf("the new token was not stored: %q", got)
	}
	o.ok() // reads with the stored token, and the provider issues another
	if got := stateOf(t, o).RegistrationAccessToken; got != "rat-1+++" {
		t.Errorf("the token after a read = %q", got)
	}
	if string(o.secret("team", "web").Data["clientSecret"]) != "dcr-secret-1" {
		t.Error("the secret was lost by an update that returned none")
	}
	f.with(func() { f.newToken = false })

	// A new secret in an update's answer replaces the stored one.
	f.with(func() { f.updateSecret = true })
	o.edit(moreRedirect("https://app.example/third"))
	o.ok()
	if string(o.secret("team", "web").Data["clientSecret"]) != "updated-secret" {
		t.Error("the secret of an update was not stored")
	}
	f.with(func() { f.updateSecret = false })

	// Rotation is a new registration: the client_id changes and the old one is
	// deleted, with no overlap.
	o.rotate("1")
	o.ok()
	c = o.get()
	if c.Status.ExternalID != "dcr-2" || stateOf(t, o).ClientID != "dcr-2" || string(o.secret("team", "web").Data["clientId"]) != "dcr-2" {
		t.Errorf("after rotation: %+v", c.Status)
	}
	f.with(func() {
		if _, ok := f.clients["dcr-1"]; ok {
			t.Error("the old registration was kept")
		}
	})
	if !o.rec.has("Normal " + conditions.EventRotatedWithoutOverlap) {
		t.Errorf("events = %v", o.rec.events)
	}

	// Deleting the claim deletes the registration and its state.
	o.del()
	o.ok()
	f.with(func() {
		if len(f.clients) != 0 {
			t.Error("the client was not deleted")
		}
	})
	if !o.gone() || o.secret(opsNS, dcr.SecretName("uid-web")) != nil {
		t.Error("the claim or its state remained")
	}
}

// A provider that answers a registration with a document the operator cannot
// use may have made the client: that is shown in a condition and an Event, and
// cleared by the next registration that works.
func TestDCRBadRegistrationAnswerIsAnOrphanRisk(t *testing.T) {
	f := startDCR(t)
	f.badRegister = true
	o := dcrOC(t, f, interceptor.Funcs{})
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a bad answer was accepted")
	}
	c := o.get()
	wantCond(t, c, conditionRegistrationUnconfirmed, metav1.ConditionTrue, reasonRegistrationUnconfirmed)
	if msg := wantCond(t, c, conditions.Synced, metav1.ConditionFalse, "").Message; !strings.Contains(msg, "unexpected document") {
		t.Errorf("message = %q", msg)
	}
	if !o.rec.has("Warning " + reasonRegistrationUnconfirmed) {
		t.Errorf("events = %v", o.rec.events)
	}
	if o.secret(opsNS, dcr.SecretName("uid-web")) != nil {
		t.Error("a registration was stored for a bad answer")
	}

	f.with(func() { f.badRegister = false })
	o.ok()
	c = o.get()
	if cond(c, conditionRegistrationUnconfirmed) != nil {
		t.Error("the condition stayed after a registration worked")
	}
	wantCond(t, c, conditions.Ready, metav1.ConditionTrue, "")
}

// A registration that cannot be stored is withdrawn, and one that cannot be
// withdrawn is an orphan risk.
func TestDCRRegistrationThatCannotBeStored(t *testing.T) {
	failStore := interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if s, ok := obj.(*corev1.Secret); ok && strings.HasPrefix(s.Name, "dcr-") {
			return errors.New("boom")
		}
		return c.Create(ctx, obj, opts...)
	}}
	f := startDCR(t)
	o := dcrOC(t, f, failStore)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a registration that cannot be stored was accepted")
	}
	f.with(func() {
		if len(f.clients) != 0 {
			t.Error("the registration was not withdrawn")
		}
	})
	if cond(o.get(), conditionRegistrationUnconfirmed) != nil {
		t.Error("a withdrawn registration is no risk")
	}

	f = startDCR(t)
	f.with(func() { f.fail["DELETE /register/dcr-1"] = 500 })
	o = dcrOC(t, f, failStore)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a registration that cannot be stored was accepted")
	}
	wantCond(t, o.get(), conditionRegistrationUnconfirmed, metav1.ConditionTrue, "")
}

// A registration the provider no longer honours, or whose state is gone, is
// Synced=False and never registered again; deleting such a claim is not held
// for it.
func TestDCRLostRegistration(t *testing.T) {
	f := startDCR(t)
	o := dcrOC(t, f, interceptor.Funcs{})
	o.ok()
	f.with(func() { delete(f.clients, "dcr-1") })
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a lost registration was not reported")
	}
	if msg := cond(o.get(), conditions.Synced).Message; !strings.Contains(msg, "no longer holds") {
		t.Errorf("message = %q", msg)
	}
	f.with(func() {
		if f.n != 1 {
			t.Error("the client was registered again")
		}
	})
	o.del()
	o.ok()
	if !o.gone() || o.secret(opsNS, dcr.SecretName("uid-web")) != nil {
		t.Error("a lost registration held its claim or its state")
	}

	// The state Secret is gone while the claim remembers a client.
	f = startDCR(t)
	o = dcrOC(t, f, interceptor.Funcs{})
	o.ok()
	if err := o.c.Delete(context.Background(), o.secret(opsNS, dcr.SecretName("uid-web"))); err != nil {
		t.Fatal(err)
	}
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a lost state was not reported")
	}
	if msg := cond(o.get(), conditions.Synced).Message; !strings.Contains(msg, "no longer holds") {
		t.Errorf("message = %q", msg)
	}
	o.del()
	o.ok()
	if !o.gone() {
		t.Error("a lost state held its claim")
	}
}

// The registration access token goes only to the registration endpoint's own
// origin: a stored management URI elsewhere is refused before any request.
func TestDCRTokenGoesToTheProvidersOriginOnly(t *testing.T) {
	f := startDCR(t)
	o := dcrOC(t, f, interceptor.Funcs{})
	o.ok()
	s := o.secret(opsNS, dcr.SecretName("uid-web"))
	s.Data[dcr.KeyRegistrationClientURI] = []byte("https://evil.example/register/dcr-1")
	if err := o.c.Update(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	reads := f.count("GET /register/dcr-1")
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a foreign management URI was accepted")
	}
	if msg := cond(o.get(), conditions.Synced).Message; !strings.Contains(msg, "stored registration is not valid") {
		t.Errorf("message = %q", msg)
	}
	if f.count("GET /register/dcr-1") != reads {
		t.Error("a request was made with a foreign management URI")
	}
}

func (f *dcrFake) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, l := range f.log {
		if l == key {
			n++
		}
	}
	return n
}

// A public client has no secret: the binding holds the client_id only, and a
// rotation request changes nothing.
func TestDCRPublicClient(t *testing.T) {
	f := startDCR(t)
	o := dcrOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = true })
	o.ok()
	o.rotate("1")
	o.ok()
	f.with(func() {
		if f.n != 1 {
			t.Errorf("registrations = %d", f.n)
		}
	})
	b := o.secret("team", "web")
	if _, has := b.Data["clientSecret"]; has || string(b.Data["clientId"]) != "dcr-1" {
		t.Errorf("binding = %v", b.Data)
	}
	// An update of a public client does not store the secret the provider
	// issued anyway.
	f.with(func() { f.updateSecret = true })
	o.edit(moreRedirect("https://app.example/two"))
	o.ok()
	if _, has := o.secret("team", "web").Data["clientSecret"]; has {
		t.Error("a public client's binding holds a secret")
	}
}

// A rotation whose old registration cannot be deleted is an orphan risk; one
// the provider no longer knows is not.
func TestDCRRotationOfAnUndeletableRegistration(t *testing.T) {
	f := startDCR(t)
	o := dcrOC(t, f, interceptor.Funcs{})
	o.ok()
	f.with(func() { f.fail["DELETE /register/dcr-1"] = 500 })
	o.rotate("1")
	o.ok()
	wantCond(t, o.get(), conditionRegistrationUnconfirmed, metav1.ConditionTrue, "")

	f = startDCR(t)
	o = dcrOC(t, f, interceptor.Funcs{})
	o.ok()
	f.with(func() { f.fail["DELETE /register/dcr-1"] = 401 })
	o.rotate("1")
	o.ok()
	if cond(o.get(), conditionRegistrationUnconfirmed) != nil {
		t.Error("a registration the provider forgot is no risk")
	}
}

// The failures of each step are reported with the fixed text of their kind.
func TestDCRFailures(t *testing.T) {
	boom := errors.New("boom")
	failSecret := func(verb string) interceptor.Funcs {
		switch verb {
		case "get":
			return interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Secret); ok && strings.HasPrefix(key.Name, "dcr-") {
					return boom
				}
				return c.Get(ctx, key, obj, opts...)
			}}
		}
		return interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if s, ok := obj.(*corev1.Secret); ok && strings.HasPrefix(s.Name, "dcr-") {
				return boom
			}
			return c.Update(ctx, obj, opts...)
		}}
	}
	for name, tc := range map[string]struct {
		prepare func(f *dcrFake)
		funcs   func() interceptor.Funcs
		change  func(*oidcv1alpha1.OidcClient)
		want    string
	}{
		"the state cannot be read": {funcs: func() interceptor.Funcs { return failSecret("get") }, want: "the operation failed"},
		"the registration cannot be read": {
			prepare: func(f *dcrFake) { f.fail["GET /register/dcr-1"] = 500 }, want: "the provider refused the request"},
		"a new token cannot be stored": {
			prepare: func(f *dcrFake) { f.newToken = true }, funcs: func() interceptor.Funcs { return failSecret("update") },
			want: "the operation failed"},
		"the update is refused": {
			prepare: func(f *dcrFake) { f.fail["PUT /register/dcr-1"] = 500 }, want: "the provider refused the request",
			change: moreRedirect("https://app.example/bye")},
		"the token of an update cannot be stored": {
			prepare: func(f *dcrFake) { f.newTokenOnPut = true }, funcs: func() interceptor.Funcs { return failSecret("update") },
			want:   "the operation failed",
			change: moreRedirect("https://app.example/bye")},
		"the old registration cannot be deleted with the claim": {
			prepare: func(f *dcrFake) { f.fail["DELETE /register/dcr-1"] = 500 }, want: "the provider refused the request"},
	} {
		t.Run(name, func(t *testing.T) {
			f := startDCR(t)
			o := dcrOC(t, f, interceptor.Funcs{})
			o.ok()
			if tc.funcs != nil {
				o.c = fakeClientWith(t, tc.funcs(), o.get(), o.secret(opsNS, dcr.SecretName("uid-web")), o.secret("team", "web"),
					secret("team", "admin", nil), caConfigMapOf("team", f.ca), dcrProviderOn(f), namespace("team"))
				o.r.Client, o.r.APIReader = o.c, o.c
				o.r.Cache = NewProviderCache(1)
			}
			if tc.prepare != nil {
				f.with(func() { tc.prepare(f) })
			}
			if tc.change != nil {
				o.edit(tc.change)
			}
			if name == "the old registration cannot be deleted with the claim" {
				o.del()
			}
			if _, err := o.reconcile(); err == nil {
				t.Fatal("the failure was not reported")
			}
			if msg := cond(o.get(), conditions.Synced).Message; !strings.Contains(msg, tc.want) {
				t.Errorf("message = %q, want %q", msg, tc.want)
			}
		})
	}
}

func dcrProviderOn(f *dcrFake) client.Object {
	p := dcrProvider("team", f.endpoint())
	p.Spec.TLS = tlsCA
	p.Spec.AllowedScopes = allowedScopes
	return p
}

// driver builds the driver of the claim on its provider, for tests that call a
// step on its own.
func (o *oc) driver(c *oidcv1alpha1.OidcClient) driver {
	o.t.Helper()
	be, err := o.r.Backend(context.Background(), c.Namespace, c.Spec.ServerRef)
	if err != nil {
		o.t.Fatal(err)
	}
	o.t.Cleanup(be.Release)
	x, err := o.r.external(context.Background(), be, c)
	if err != nil {
		o.t.Fatal(err)
	}
	return x.drv
}

// A binding that does not hold the secret of a confidential client cannot be
// completed by an update that returns none: the next reconcile issues a new
// secret instead.
func TestDCRUpdateWithoutAKnownSecret(t *testing.T) {
	f := startDCR(t)
	o := dcrOC(t, f, interceptor.Funcs{})
	o.ok()
	c := o.get()
	d := o.driver(c).(*dcrDriver)
	if err := o.c.Delete(context.Background(), o.secret("team", "web")); err != nil {
		t.Fatal(err)
	}
	w, _ := resolveSpec(c.Spec, allowedScopes)
	if _, err := d.update(context.Background(), w, clientState{reg: stateOf(t, o)}); !errors.Is(err, ErrBindingNotUsable) {
		t.Errorf("update = %v", err)
	}
	// A binding read that fails is an error too.
	d.cfg.APIReader = fakeClientWith(t, interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
		return errors.New("boom")
	}})
	if _, err := d.update(context.Background(), w, clientState{reg: stateOf(t, o)}); err == nil {
		t.Error("a failing read of the binding was ignored")
	}
	// The status write after a registration is a failure too.
	d.persist = func(context.Context) error { return errors.New("boom") }
	if _, err := d.create(context.Background(), w); err == nil {
		t.Error("a failing status write was ignored")
	}
	// A rotation whose registration fails is reported.
	f.with(func() { f.badRegister = true })
	if _, err := d.rotateBegin(context.Background(), w, clientState{reg: stateOf(t, o)}); !errors.Is(err, idpclient.ErrBadResponse) {
		t.Errorf("rotateBegin = %v", err)
	}
	if err := d.rotateFinish(context.Background()); err != nil || !d.hardCut() {
		t.Errorf("rotateFinish = %v", err)
	}
}

// The steps of the Keycloak driver report the failure of each request.
func TestKeycloakDriverFailures(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		fail string
		step func(d *keycloakDriver, w clientSpec) error
	}{
		"create is refused": {"POST /clients", func(d *keycloakDriver, w clientSpec) error { _, err := d.create(ctx, w); return err }},
		"the secret of a new client cannot be read": {"GET /clients/kc-1/client-secret",
			func(d *keycloakDriver, w clientSpec) error {
				d.claim.SetExternalID("")
				d.k = &failFirstGet{keycloakAPI: d.k}
				_, err := d.create(ctx, w)
				return err
			}},
		"the status cannot be written": {"", func(d *keycloakDriver, w clientSpec) error {
			d.persist = func(context.Context) error { return errors.New("boom") }
			d.claim.SetExternalName(idpclient.KeycloakClientID("team", "fresh"))
			_, err := d.create(ctx, w)
			return err
		}},
		"update is refused": {"PUT /clients/kc-1", func(d *keycloakDriver, w clientSpec) error {
			_, err := d.update(ctx, w, clientState{kc: idpclient.Client{ID: "kc-1"}})
			return err
		}},
		"the secret after an update cannot be read": {"GET /clients/kc-1/client-secret", func(d *keycloakDriver, w clientSpec) error {
			_, err := d.update(ctx, w, clientState{kc: idpclient.Client{ID: "kc-1"}})
			return err
		}},
		"the binding cannot be read for a rotation": {"", func(d *keycloakDriver, w clientSpec) error {
			d.cfg.APIReader = fakeClientWith(t, interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return errors.New("boom")
			}})
			_, err := d.rotateBegin(ctx, w, clientState{})
			return err
		}},
		"the rotation is refused": {"POST /clients/kc-1/client-secret", func(d *keycloakDriver, w clientSpec) error {
			_, err := d.rotateBegin(ctx, w, clientState{})
			return err
		}},
		"the previous secret cannot be retired": {"DELETE /clients/kc-1/client-secret/rotated", func(d *keycloakDriver, w clientSpec) error {
			return d.rotateFinish(ctx)
		}},
		"observe is refused": {"GET /clients/kc-1", func(d *keycloakDriver, w clientSpec) error {
			_, err := d.observe(ctx, w, nil)
			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := startIDP(t)
			o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient())...)
			o.ok()
			c := o.get()
			d := o.driver(c).(*keycloakDriver)
			d.persist = func(context.Context) error { return nil }
			if tc.fail != "" {
				f.kc.failing(tc.fail, 500)
			}
			w, _ := resolveSpec(c.Spec, allowedScopes)
			if err := tc.step(d, w); err == nil {
				t.Error("the failure was ignored")
			}
		})
	}
}

// failFirstGet makes the read of a secret fail.
type failFirstGet struct{ keycloakAPI }

func (failFirstGet) Secret(context.Context, string) (string, error) { return "", errors.New("boom") }

func TestDriversHardCut(t *testing.T) {
	d := &keycloakDriver{}
	if d.hardCut() {
		t.Error("a rotation with an unknown outcome is not a hard cut")
	}
	d.noOverlap = true
	if !d.hardCut() {
		t.Error("a rotation without overlap is a hard cut")
	}
}
