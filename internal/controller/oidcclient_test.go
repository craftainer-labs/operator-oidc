package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/dcr"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

var testNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// oc is a reconciler over a fake API server, with a clock and a recorder.
type oc struct {
	t   *testing.T
	c   client.Client
	r   *ClientReconciler
	rec *recorder
	now time.Time
}

func newOC(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) *oc {
	t.Helper()
	c := fakeClientWith(t, funcs, objs...)
	o := &oc{t: t, c: c, rec: &recorder{}, now: testNow}
	cfg := config(c)
	cfg.APIReader, cfg.Recorder, cfg.ManagedBy = c, o.rec, "operator-oidc"
	cfg.Now = func() time.Time { return o.now }
	o.r = &ClientReconciler{Config: cfg}
	return o
}

func (o *oc) reconcile() (ctrl.Result, error) {
	o.t.Helper()
	return o.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Namespace: "team", Name: "web"}})
}

// ok reconciles and fails the test on an error.
func (o *oc) ok() {
	o.t.Helper()
	if _, err := o.reconcile(); err != nil {
		o.t.Fatalf("reconcile: %v", err)
	}
}

func (o *oc) get() *oidcv1alpha1.OidcClient {
	o.t.Helper()
	var c oidcv1alpha1.OidcClient
	if err := o.c.Get(context.Background(), client.ObjectKey{Namespace: "team", Name: "web"}, &c); err != nil {
		o.t.Fatal(err)
	}
	return &c
}

func (o *oc) gone() bool {
	var c oidcv1alpha1.OidcClient
	return apierrors.IsNotFound(o.c.Get(context.Background(), client.ObjectKey{Namespace: "team", Name: "web"}, &c))
}

func (o *oc) secret(ns, name string) *corev1.Secret {
	o.t.Helper()
	var s corev1.Secret
	err := o.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &s)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		o.t.Fatal(err)
	}
	return &s
}

func (o *oc) edit(mut func(*oidcv1alpha1.OidcClient)) {
	o.t.Helper()
	c := o.get()
	mut(c)
	if err := o.c.Update(context.Background(), c); err != nil {
		o.t.Fatal(err)
	}
}

func (o *oc) rotate(trigger string) {
	o.t.Helper()
	o.edit(func(c *oidcv1alpha1.OidcClient) {
		if c.Annotations == nil {
			c.Annotations = map[string]string{}
		}
		c.Annotations[lifecycle.AnnotationRotate] = trigger
	})
}

func (o *oc) del() {
	o.t.Helper()
	if err := o.c.Delete(context.Background(), o.get()); err != nil {
		o.t.Fatal(err)
	}
}

func cond(c *oidcv1alpha1.OidcClient, typ string) *metav1.Condition {
	return meta.FindStatusCondition(c.Status.Conditions, typ)
}

func wantCond(t *testing.T, c *oidcv1alpha1.OidcClient, typ string, status metav1.ConditionStatus, reason string) *metav1.Condition {
	t.Helper()
	got := cond(c, typ)
	if got == nil || got.Status != status || (reason != "" && got.Reason != reason) {
		t.Fatalf("condition %s = %+v, want %s %s", typ, got, status, reason)
	}
	return got
}

// oidcClient is a confidential client of the namespaced provider "kc".
func oidcClient(mut ...func(*oidcv1alpha1.OidcClient)) *oidcv1alpha1.OidcClient {
	c := &oidcv1alpha1.OidcClient{ObjectMeta: metav1.ObjectMeta{
		Namespace: "team", Name: "web", UID: "uid-web", Generation: 1, CreationTimestamp: metav1.NewTime(testNow.Add(-24 * time.Hour)),
	}}
	c.Spec.ServerRef = ref(kindIdentityProvider, "kc")
	c.Spec.RedirectURIs = []oidcv1alpha1.RedirectURI{"https://app.example/cb"}
	c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "profile"}
	for _, m := range mut {
		m(c)
	}
	return c
}

var allowedScopes = []oidcv1alpha1.Scope{"openid", "profile", "email"}

// kcObjects are a namespace, the admin Secret, the CA and a provider on f.
func kcObjects(f *idp) []client.Object {
	p := keycloakProvider("team", f)
	p.Spec.AllowedScopes = allowedScopes
	return []client.Object{namespace("team"), secret("team", "admin", adminCreds), caConfigMap("team", f), p}
}

// dcrObjects are the same for a provider that registers clients on f.
func dcrObjects(f *dcrFake) []client.Object {
	p := dcrProvider("team", f.endpoint())
	p.Spec.TLS = tlsCA
	p.Spec.AllowedScopes = allowedScopes
	return []client.Object{namespace("team"), secret("team", "admin", nil), caConfigMapOf("team", f.ca), p}
}

func with(objs []client.Object, more ...client.Object) []client.Object { return append(objs, more...) }

func sortedDefaults(f *idp, id string) []string {
	var out []string
	f.kc.with(func() { out = slices.Sorted(slices.Values(f.kc.defaults[id])) })
	return out
}

func eqStrings(a, b []string) bool { return slices.Equal(a, b) }

// A client on Keycloak is made with exactly the spec's scopes, left alone while
// it matches, corrected when it drifts, rotated with an overlap and deleted
// with its claim.
func TestKeycloakClientLifecycle(t *testing.T) {
	f := startIDP(t)
	o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient())...)

	o.ok()
	c := o.get()
	wantCond(t, c, conditions.Ready, metav1.ConditionTrue, "")
	name := idpclient.KeycloakClientID("team", "web")
	if c.Status.ExternalID != "kc-1" || c.Status.ExternalName != name {
		t.Fatalf("status = %q %q", c.Status.ExternalID, c.Status.ExternalName)
	}
	s := o.secret("team", "web")
	if s == nil || string(s.Data["clientId"]) != name || string(s.Data["clientSecret"]) != "secret-1-0" ||
		string(s.Data["issuer"]) != f.issuer() {
		t.Fatalf("binding = %v", s)
	}
	// Exact scopes: the realm's roles and email are removed, and basic stays.
	if got := sortedDefaults(f, "kc-1"); !eqStrings(got, []string{"basic", "profile"}) {
		t.Errorf("default client scopes = %v", got)
	}
	if b, _ := json.Marshal(c.Status); strings.Contains(string(b), "secret-1-0") {
		t.Errorf("a secret reached the status: %s", b)
	}

	// A matching client is not written again.
	o.ok()
	if f.kc.saw("PUT /clients/kc-1") {
		t.Fatal("a matching client was updated")
	}

	// Drift in the redirect URIs and in the scopes is corrected, once each.
	f.kc.with(func() { f.kc.clients["kc-1"]["redirectUris"] = []any{"https://evil.example/cb"} })
	o.ok()
	f.kc.with(func() { f.kc.defaults["kc-1"] = append(f.kc.defaults["kc-1"], "email") })
	o.ok()
	if n := f.kc.count("PUT /clients/kc-1"); n != 2 {
		t.Errorf("updates = %d", n)
	}
	if got := sortedDefaults(f, "kc-1"); !eqStrings(got, []string{"basic", "profile"}) {
		t.Errorf("default client scopes after drift = %v", got)
	}

	// A rotation keeps the previous secret valid for the grace period.
	o.rotate("1")
	o.ok()
	if s := o.secret("team", "web"); string(s.Data["clientSecret"]) != "secret-1-0+" {
		t.Errorf("rotated secret = %q", s.Data["clientSecret"])
	}
	if c := o.get(); c.Status.Rotation == nil || c.Status.Rotation.RetireAfter == nil {
		t.Fatalf("rotation = %+v", c.Status.Rotation)
	}
	o.now = o.now.Add(2 * time.Hour)
	o.ok()
	if !f.kc.saw("DELETE /clients/kc-1/client-secret/rotated") {
		t.Error("the previous secret was not invalidated after the grace period")
	}

	// Deleting the claim deletes the client.
	o.del()
	o.ok()
	if !o.gone() || len(f.kc.clients) != 0 {
		t.Errorf("claim gone = %v, clients = %d", o.gone(), len(f.kc.clients))
	}
}

// A realm without a rotation policy kills the previous secret at once, which is
// a hard cut with its own Event.
func TestKeycloakRotationWithoutOverlap(t *testing.T) {
	f := startIDP(t)
	f.kc.noRotated = true
	o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient())...)
	o.ok()
	o.rotate("1")
	o.ok()
	if !o.rec.has("Normal " + conditions.EventRotatedWithoutOverlap) {
		t.Errorf("events = %v", o.rec.events)
	}
	if c := o.get(); c.Status.Rotation == nil || c.Status.Rotation.RetireAfter != nil {
		t.Errorf("rotation = %+v", c.Status.Rotation)
	}
}

// A public client has no secret to read or rotate.
func TestKeycloakPublicClient(t *testing.T) {
	f := startIDP(t)
	pub := oidcClient(func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = true })
	o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), pub)...)
	o.ok()
	o.rotate("1")
	o.ok()
	s := o.secret("team", "web")
	if _, has := s.Data["clientSecret"]; has || f.kc.saw("POST /clients/kc-1/client-secret") || f.kc.saw("GET /clients/kc-1/client-secret") {
		t.Errorf("a public client's secret was read or written: %v", s.Data)
	}
	wantCond(t, o.get(), conditions.Ready, metav1.ConditionTrue, "")
}

// The binding carries the discovery document's endpoints once a probe found
// them.
func TestKeycloakBindingCarriesDiscovery(t *testing.T) {
	f := startIDP(t)
	objs := kcObjects(f)
	objs[3].(*oidcv1alpha1.IdentityProvider).Status.Discovery = &oidcv1alpha1.Discovery{
		AuthorizationEndpoint: "https://sso.example/auth", JWKSURI: "https://sso.example/certs",
	}
	o := newOC(t, interceptor.Funcs{}, with(objs, oidcClient())...)
	o.ok()
	s := o.secret("team", "web")
	if string(s.Data["authorizationEndpoint"]) != "https://sso.example/auth" || string(s.Data["jwksUri"]) != "https://sso.example/certs" {
		t.Errorf("binding = %v", s.Data)
	}
	if _, has := s.Data["userinfoEndpoint"]; has {
		t.Errorf("an unknown endpoint was written: %v", s.Data)
	}
}

// A client of the claim's name is adopted when it carries the claim's marker
// and refused when it does not.
func TestKeycloakAdoptionAndCollision(t *testing.T) {
	name := idpclient.KeycloakClientID("team", "web")
	for _, tc := range []struct {
		marker string
		reason string
	}{
		{idpclient.Marker("team", "web", "uid-web"), ""},
		{"team/other/uid-other", conditions.NameCollision},
	} {
		f := startIDP(t)
		o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient())...)
		// The realm already holds a client of that name.
		f.kc.with(func() {
			f.kc.clients = map[string]map[string]any{"kc-9": {
				"id": "kc-9", "clientId": name, "attributes": map[string]any{"craftainer.dev/claim": tc.marker},
			}}
			f.kc.defaults = map[string][]string{"kc-9": nil}
			f.kc.secrets = map[string]string{"kc-9": "adopted"}
			f.kc.rotated = map[string]string{}
		})
		_, _ = o.reconcile()
		c := o.get()
		if tc.reason == "" {
			wantCond(t, c, conditions.Ready, metav1.ConditionTrue, "")
			if c.Status.ExternalID != "kc-9" || string(o.secret("team", "web").Data["clientSecret"]) != "adopted" {
				t.Errorf("adoption: %q", c.Status.ExternalID)
			}
			continue
		}
		wantCond(t, c, conditions.Synced, metav1.ConditionFalse, tc.reason)
		if o.secret("team", "web") != nil {
			t.Error("a binding Secret was written for a client that is not ours")
		}
	}
}

// A spec the CRD and the webhook would have refused is refused again, before
// anything is made at the provider, and deleting such a claim still works.
func TestKeycloakInvalidSpecIsRefusedAgain(t *testing.T) {
	for name, mut := range map[string]func(*oidcv1alpha1.OidcClient){
		"http on a confidential client": func(c *oidcv1alpha1.OidcClient) {
			c.Spec.RedirectURIs = []oidcv1alpha1.RedirectURI{"http://localhost/cb"}
		},
		"a scope the provider does not allow": func(c *oidcv1alpha1.OidcClient) {
			c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "admin"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := startIDP(t)
			o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient(mut))...)
			if _, err := o.reconcile(); err == nil {
				t.Fatal("an invalid claim was accepted")
			}
			c := o.get()
			msg := wantCond(t, c, conditions.Synced, metav1.ConditionFalse, "").Message
			if !strings.Contains(msg, "the client's spec is not valid") && !strings.Contains(msg, "not allowed by the provider") {
				t.Errorf("message = %q", msg)
			}
			f.kc.with(func() {
				if len(f.kc.clients) != 0 {
					t.Error("a client was made")
				}
			})
		})
	}

	// A client that exists keeps working to be deleted when its spec is bad.
	f := startIDP(t)
	o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient())...)
	o.ok()
	o.edit(func(c *oidcv1alpha1.OidcClient) {
		c.Spec.RedirectURIs = []oidcv1alpha1.RedirectURI{"http://localhost/cb"}
	})
	if _, err := o.reconcile(); err == nil {
		t.Fatal("an invalid update was accepted")
	}
	if f.kc.saw("PUT /clients/kc-1") {
		t.Error("an invalid spec was sent to the provider")
	}
	o.del()
	o.ok()
	if !o.gone() {
		t.Error("the claim was not deleted")
	}
}

// A client someone deleted at the provider is made again, and a failing
// provider shows one fixed text.
func TestKeycloakObserveFailures(t *testing.T) {
	f := startIDP(t)
	o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient())...)
	o.ok()
	f.kc.with(func() { delete(f.kc.clients, "kc-1") })
	o.ok()
	if c := o.get(); c.Status.ExternalID != "kc-2" {
		t.Errorf("externalId = %q", c.Status.ExternalID)
	}

	f.kc.failing("GET /clients/kc-2", 500)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a failing provider was not reported")
	}
	msg := cond(o.get(), conditions.Synced).Message
	if !strings.Contains(msg, "the provider refused the request") || strings.Contains(msg, "500") {
		t.Errorf("message = %q", msg)
	}
}

// A claim whose provider is gone says so; one that never made a client is
// released without the provider; a provider whose client cannot be built is
// refused with a fixed text.
func TestClientWithoutUsableProvider(t *testing.T) {
	o := newOC(t, interceptor.Funcs{}, namespace("team"), oidcClient())
	if _, err := o.reconcile(); err != nil {
		t.Fatalf("a missing provider is a final state: %v", err)
	}
	wantCond(t, o.get(), conditions.Synced, metav1.ConditionFalse, conditions.ServerNotFound)
	o.del()
	o.ok()
	if !o.gone() {
		t.Error("a claim that made nothing was held by its finalizer")
	}
	// A claim that does not exist is not an error.
	if _, err := o.reconcile(); err != nil {
		t.Error(err)
	}

	f := startIDP(t)
	objs := kcObjects(f)
	objs[3].(*oidcv1alpha1.IdentityProvider).Spec.Keycloak.Realm = ".."
	o = newOC(t, interceptor.Funcs{}, with(objs, oidcClient())...)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a provider that cannot be used was accepted")
	}
	if msg := cond(o.get(), conditions.Synced).Message; !strings.Contains(msg, invalidProvider) {
		t.Errorf("message = %q", msg)
	}
}

// A client of a provider that cannot be reached is not Ready, ServerReachable
// says False and nothing of the address is shown.
func TestClientOfUnreachableProvider(t *testing.T) {
	f := startIDP(t)
	f.srv.Close()
	o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient())...)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("an unreachable provider was not reported")
	}
	c := o.get()
	wantCond(t, c, conditions.ServerReachable, metav1.ConditionFalse, conditions.ServerUnreachable)
	if b, _ := json.Marshal(c.Status.Conditions); strings.Contains(string(b), "127.0.0.1") {
		t.Errorf("an address reached the conditions: %s", b)
	}
}

// resolveSpec resolves the defaults and refuses what the CRD and the webhook
// refuse.
func TestResolveSpec(t *testing.T) {
	https := []oidcv1alpha1.RedirectURI{"https://app.example/cb"}
	allowed := allowedScopes
	w, err := resolveSpec(oidcv1alpha1.OidcClientSpec{RedirectURIs: https}, allowed)
	if err != nil || !eqStrings(w.grants, []string{"authorization_code"}) || !eqStrings(w.scopes, []string{"openid"}) ||
		w.pkce != "S256" || w.method != "client_secret_basic" {
		t.Errorf("defaults: %+v, %v", w, err)
	}
	w, err = resolveSpec(oidcv1alpha1.OidcClientSpec{Public: true, RedirectURIs: []oidcv1alpha1.RedirectURI{"http://localhost:8080/cb"}}, allowed)
	if err != nil || w.method != "none" {
		t.Errorf("public: %+v, %v", w, err)
	}
	if _, err := resolveSpec(oidcv1alpha1.OidcClientSpec{
		GrantTypes: []oidcv1alpha1.GrantType{"client_credentials"}, PostLogoutRedirectURIs: https, WebOrigins: []oidcv1alpha1.WebOrigin{"https://app.example"},
	}, allowed); err != nil {
		t.Errorf("a client_credentials client needs no redirect URI: %v", err)
	}

	for name, spec := range map[string]oidcv1alpha1.OidcClientSpec{
		"no redirect URI":      {},
		"http redirect":        {RedirectURIs: []oidcv1alpha1.RedirectURI{"http://localhost/cb"}},
		"wildcard":             {RedirectURIs: []oidcv1alpha1.RedirectURI{"https://*.example/cb"}},
		"bad post logout":      {RedirectURIs: https, PostLogoutRedirectURIs: []oidcv1alpha1.RedirectURI{"javascript:alert(1)"}},
		"web origin with path": {RedirectURIs: https, WebOrigins: []oidcv1alpha1.WebOrigin{"https://app.example/path"}},
		"public client_credentials": {Public: true, RedirectURIs: https,
			GrantTypes: []oidcv1alpha1.GrantType{"authorization_code", "client_credentials"}},
		"public without PKCE": {Public: true, RedirectURIs: https, PKCE: oidcv1alpha1.PKCEDisabled},
		"none on a confidential client": {RedirectURIs: https,
			TokenEndpointAuthMethod: oidcv1alpha1.AuthMethodNone},
		"a secret method on a public client": {Public: true, RedirectURIs: https,
			TokenEndpointAuthMethod: oidcv1alpha1.AuthMethodClientSecretPost},
	} {
		if _, err := resolveSpec(spec, allowed); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := resolveSpec(oidcv1alpha1.OidcClientSpec{RedirectURIs: https, Scopes: []oidcv1alpha1.Scope{"admin"}}, allowed); !errors.Is(err, ErrScopeNotAllowed) {
		t.Errorf("a scope the provider does not allow: %v", err)
	}
	if _, err := resolveSpec(oidcv1alpha1.OidcClientSpec{RedirectURIs: https}, nil); !errors.Is(err, ErrScopeNotAllowed) {
		t.Errorf("a provider that allows no scope: %v", err)
	}
}

// The OnOrphan hook keeps the registration state of a client the operator stops
// managing.
func TestOrphanKeepsRegistrationState(t *testing.T) {
	f := startDCR(t)
	o := dcrOC(t, f, interceptor.Funcs{})
	o.ok()
	if err := o.r.options(nil).OnOrphan(context.Background(), o.get()); err != nil {
		t.Fatal(err)
	}
	s := o.secret(opsNS, dcr.SecretName("uid-web"))
	if s == nil || s.Labels[dcr.LabelOrphaned] != "true" {
		t.Errorf("state = %v", s)
	}
}

// The providers' watches map a provider to the clients that name it.
func TestClientsOfProvider(t *testing.T) {
	a := oidcClient()
	b := oidcClient(func(c *oidcv1alpha1.OidcClient) { c.Name, c.UID = "other", "uid-other" })
	cl := oidcClient(func(c *oidcv1alpha1.OidcClient) {
		c.Name, c.UID = "cluster", "uid-cluster"
		c.Spec.ServerRef = ref(kindClusterIdentityProvider, "kc")
	})
	m := fakeClient(t, a, b, cl)
	ctx := context.Background()

	reqs := clientsOfProvider(m, kindIdentityProvider)(ctx, &oidcv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "kc"}})
	if len(reqs) != 2 {
		t.Errorf("namespaced provider: %v", reqs)
	}
	reqs = clientsOfProvider(m, kindIdentityProvider)(ctx, &oidcv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Namespace: "elsewhere", Name: "kc"}})
	if len(reqs) != 0 {
		t.Errorf("another namespace: %v", reqs)
	}
	reqs = clientsOfProvider(m, kindClusterIdentityProvider)(ctx, &oidcv1alpha1.ClusterIdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "kc"}})
	if len(reqs) != 1 || reqs[0].Name != "cluster" {
		t.Errorf("cluster provider: %v", reqs)
	}
	// A list that fails maps to nothing.
	broken := fakeClientWith(t, interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
		return errors.New("boom")
	}})
	if reqs := clientsOfProvider(broken, kindIdentityProvider)(ctx, &oidcv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "kc"}}); reqs != nil {
		t.Errorf("a failing list: %v", reqs)
	}

	// Only a changed spec of a provider reconciles its clients.
	old, upd := &oidcv1alpha1.IdentityProvider{}, &oidcv1alpha1.IdentityProvider{}
	upd.Generation = 2
	if providerChanged.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: old}) || !providerChanged.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: upd}) {
		t.Error("providerChanged filter")
	}
}

func TestBindingSecretOfAnotherOwnerIsNotRead(t *testing.T) {
	f := startIDP(t)
	foreign := secret("team", "web", map[string]string{"clientSecret": "someone-elses"})
	o := newOC(t, interceptor.Funcs{}, with(kcObjects(f), oidcClient(), foreign)...)
	b := base{cfg: o.r.Config, claim: o.get()}
	got, err := b.currentSecret(context.Background())
	if err != nil || got != "" {
		t.Errorf("a Secret the claim does not control was read: %q, %v", got, err)
	}
	// Without an API reader the client reads.
	b.cfg.APIReader = nil
	if got, err := b.currentSecret(context.Background()); err != nil || got != "" {
		t.Errorf("client read: %q, %v", got, err)
	}
	boom := errors.New("boom")
	b.cfg.APIReader = fakeClientWith(t, interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
		return boom
	}})
	if _, err := b.currentSecret(context.Background()); !errors.Is(err, boom) {
		t.Errorf("a failing read: %v", err)
	}
}

// A provider whose DCR client cannot be built is refused with a fixed text.
func TestClientOfADCRProviderThatCannotBeBuilt(t *testing.T) {
	p := dcrProvider("team", "http://idp.example/register")
	p.Spec.AllowedScopes = allowedScopes
	claim := oidcClient(func(c *oidcv1alpha1.OidcClient) { c.Spec.ServerRef = ref(kindIdentityProvider, "dcr") })
	o := newOC(t, interceptor.Funcs{}, namespace("team"), secret("team", "admin", nil), p, claim)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a provider that cannot be used was accepted")
	}
	if msg := cond(o.get(), conditions.Synced).Message; !strings.Contains(msg, invalidProvider) {
		t.Errorf("message = %q", msg)
	}
}

// The texts of the failures an OidcClient adds, and the failures that mean the
// provider could not be reached.
func TestClientErrorTexts(t *testing.T) {
	for err, text := range map[error]string{
		lifecycle.ErrNameCollision:        "a client of that name exists and this claim did not make it",
		idpclient.ErrUnknownScope:         "a scope of the client is not a client scope of the provider's realm",
		idpclient.ErrRegistrationLost:     "the provider no longer holds the client's registration",
		idpclient.ErrInvalidState:         "the stored registration is not valid",
		idpclient.ErrInvalidSpec:          invalidClient,
		idpclient.ErrInvalidID:            invalidClient,
		ErrInvalidClient:                  ErrInvalidClient.Error(),
		ErrScopeNotAllowed:                ErrScopeNotAllowed.Error(),
		ErrBindingNotUsable:               ErrBindingNotUsable.Error(),
		errors.New("https://idp.example"): defaultText,
	} {
		in := err // an error of this package carries its own fixed text
		if text != err.Error() {
			in = fmt.Errorf("%w at https://idp.example/x?token=1", err)
		}
		if got := categoryOnly(in); !strings.HasPrefix(got.Error(), text) || strings.Contains(got.Error(), "idp.example/x") {
			t.Errorf("%v: %q", err, got)
		}
	}
	for _, err := range []error{idpclient.ErrConnPolicy, idpclient.ErrConnTLS, idpclient.ErrConnTimeout, idpclient.ErrConnFailed} {
		if got := categoryOnly(err); !errors.Is(got, lifecycle.ErrUnreachable) || !errors.Is(got, err) {
			t.Errorf("%v: %v", err, got)
		}
	}
	if got := categoryOnly(idpclient.ErrConnAuth); errors.Is(got, lifecycle.ErrUnreachable) {
		t.Error("a refused credential is not an unreachable provider")
	}
}

// A claim that never made a client has nothing to observe, create, update or
// delete, and a spec the controller refuses does not rotate.
func TestNothingMadeAndInvalidRotation(t *testing.T) {
	ctx := context.Background()
	var n nothingMade
	if obs, err := n.Observe(ctx, oidcv1alpha1.OidcClientSpec{}); err != nil || obs.Exists {
		t.Errorf("observe: %v, %v", obs, err)
	}
	if d, err := n.Create(ctx, oidcv1alpha1.OidcClientSpec{}); d != nil || err != nil {
		t.Errorf("create: %v, %v", d, err)
	}
	if d, err := n.Update(ctx, oidcv1alpha1.OidcClientSpec{}, clientState{}); d != nil || err != nil {
		t.Errorf("update: %v, %v", d, err)
	}
	if err := n.Delete(ctx, clientState{}); err != nil {
		t.Errorf("delete: %v", err)
	}
	x := &clientExternal{wantErr: ErrInvalidClient}
	if _, _, err := x.RotateBegin(ctx, oidcv1alpha1.OidcClientSpec{}, clientState{}, lifecycle.RotationState{}); !errors.Is(err, ErrInvalidClient) {
		t.Errorf("rotate: %v", err)
	}
}

// failingDriver fails a rotation.
type failingDriver struct{ driver }

func (failingDriver) rotateBegin(context.Context, clientSpec, clientState) (binding.Data, error) {
	return nil, idpclient.ErrConnFailed
}

// A rotation the provider refuses is reported with the fixed text of its kind.
func TestRotationFailureIsCoarse(t *testing.T) {
	x := &clientExternal{drv: failingDriver{}}
	_, _, err := x.RotateBegin(context.Background(), oidcv1alpha1.OidcClientSpec{}, clientState{}, lifecycle.RotationState{})
	if !errors.Is(err, lifecycle.ErrUnreachable) || err.Error() != "the connection to the provider failed" {
		t.Errorf("rotate: %v", err)
	}
}
