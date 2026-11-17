package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

const testTenant = "11111111-2222-3333-4444-555555555555"

func guidN(prefix string, n int) string {
	return fmt.Sprintf("%s0000000-0000-0000-0000-%012d", prefix, n)
}

// graphStatus is an HTTP answer of Graph as idpclient shapes the error.
func graphStatus(status int) error { return &idpclient.Error{Status: status} }

// fakeGraph is the part of Microsoft Graph the operator uses, over one tenant:
// the applications are what the calls made them.
type fakeGraph struct {
	mu   sync.Mutex
	apps map[string]*idpclient.GraphApp
	// secrets maps a key ID to the secret text it was issued with.
	secrets map[string]string
	n, k    int
	calls   []string
	created []idpclient.GraphApp
	// failOp maps "probe", "create", "get", "update", "delete", "add" and
	// "remove" to the error the fake answers.
	failOp map[string]error
	// createEmpty makes a create answer without IDs (an unexpected document).
	createEmpty bool
}

func newFakeGraph() *fakeGraph {
	return &fakeGraph{apps: map[string]*idpclient.GraphApp{}, secrets: map[string]string{}, failOp: map[string]error{}}
}

func (f *fakeGraph) enter(op string) error {
	f.calls = append(f.calls, op)
	return f.failOp[op]
}

func (f *fakeGraph) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == op {
			n++
		}
	}
	return n
}

func (f *fakeGraph) with(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

// keys are the key IDs of an application, in order.
func (f *fakeGraph) keys(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, p := range f.apps[id].Passwords {
		out = append(out, p.KeyID)
	}
	return out
}

func (f *fakeGraph) Probe(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enter("probe")
}

func (f *fakeGraph) Get(_ context.Context, id string) (idpclient.GraphApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("get"); err != nil {
		return idpclient.GraphApp{}, err
	}
	a, ok := f.apps[id]
	if !ok {
		return idpclient.GraphApp{}, graphStatus(404)
	}
	out := *a
	out.Passwords = slices.Clone(a.Passwords)
	return out, nil
}

func (f *fakeGraph) Create(_ context.Context, a idpclient.GraphApp) (idpclient.GraphApp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("create"); err != nil {
		return idpclient.GraphApp{}, err
	}
	f.created = append(f.created, a)
	if f.createEmpty {
		return idpclient.GraphApp{}, idpclient.ErrBadResponse
	}
	f.n++
	a.ID, a.AppID, a.Passwords = guidN("a", f.n), guidN("b", f.n), nil
	f.apps[a.ID] = &a
	return a, nil
}

func (f *fakeGraph) Update(_ context.Context, id string, a idpclient.GraphApp) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("update"); err != nil {
		return err
	}
	cur, ok := f.apps[id]
	if !ok {
		return graphStatus(404)
	}
	a.ID, a.AppID, a.Passwords = cur.ID, cur.AppID, cur.Passwords
	f.apps[id] = &a
	return nil
}

func (f *fakeGraph) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("delete"); err != nil {
		return err
	}
	if _, ok := f.apps[id]; !ok {
		return graphStatus(404)
	}
	delete(f.apps, id)
	return nil
}

func (f *fakeGraph) AddPassword(_ context.Context, id, name string) (idpclient.GraphSecret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("add"); err != nil {
		return idpclient.GraphSecret{}, err
	}
	a, ok := f.apps[id]
	if !ok {
		return idpclient.GraphSecret{}, graphStatus(404)
	}
	f.k++
	key, text := guidN("c", f.k), fmt.Sprintf("secret-%d", f.k)
	a.Passwords = append(a.Passwords, idpclient.GraphPassword{KeyID: key, DisplayName: name})
	f.secrets[key] = text
	return idpclient.GraphSecret{KeyID: key, Value: text}, nil
}

func (f *fakeGraph) RemovePassword(_ context.Context, id, keyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("remove"); err != nil {
		return err
	}
	a, ok := f.apps[id]
	if !ok {
		return graphStatus(404)
	}
	a.Passwords = slices.DeleteFunc(a.Passwords, func(p idpclient.GraphPassword) bool { return p.KeyID == keyID })
	return nil
}

// graphFactory is Config.Entra for a test: every client is f.
func graphFactory(f *fakeGraph) func(*cloud.AzureClient) (GraphAPI, error) {
	return func(*cloud.AzureClient) (GraphAPI, error) { return f, nil }
}

// entraProvider is a cluster provider of type Entra that every namespace may
// use, with a client secret in the operator namespace.
func entraProvider() *oidcv1alpha1.ClusterIdentityProvider {
	p := &oidcv1alpha1.ClusterIdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "ent", UID: "uid-ent", Generation: 1}}
	p.Spec.ProviderConfig = oidcv1alpha1.ProviderConfig{
		Type: oidcv1alpha1.ProviderEntra, AllowedScopes: append(slices.Clone(allowedScopes), "offline_access"),
		Entra: &oidcv1alpha1.EntraConfig{AzureClusterBlock: cloud.AzureClusterBlock{AzureBlock: cloud.AzureBlock{TenantID: testTenant}}},
	}
	p.Spec.Credentials = &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "azure", Namespace: opsNS}}
	p.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesAll}
	return p
}

var azureKeys = map[string]string{"clientId": "00000000-0000-0000-0000-000000000001", "clientSecret": "not-a-secret"}

func entraObjects() []client.Object {
	return []client.Object{namespace("team"), secret(opsNS, "azure", azureKeys), entraProvider()}
}

func entraClaim(mut ...func(*oidcv1alpha1.OidcClient)) *oidcv1alpha1.OidcClient {
	return oidcClient(append([]func(*oidcv1alpha1.OidcClient){
		func(c *oidcv1alpha1.OidcClient) { c.Spec.ServerRef = ref(kindClusterIdentityProvider, "ent") },
	}, mut...)...)
}

func newEntraOC(t *testing.T, f *fakeGraph, funcs interceptor.Funcs, mut ...func(*oidcv1alpha1.OidcClient)) *oc {
	t.Helper()
	o := newOC(t, funcs, with(entraObjects(), entraClaim(mut...))...)
	o.r.Entra = graphFactory(f)
	return o
}

// An application is made with exactly the claim's settings and one secret, left
// alone while it matches, corrected when it drifts and deleted with the claim;
// the binding Secret holds the issuer, the endpoints, the application ID and the
// secret.
func TestEntraClientLifecycle(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) {
		c.Spec.PostLogoutRedirectURIs = []oidcv1alpha1.RedirectURI{"https://app.example/bye"}
	})

	o.ok()
	c := o.get()
	wantCond(t, c, conditions.Ready, metav1.ConditionTrue, "")
	name := idpclient.EntraAppName("team", "web")
	id, appID := guidN("a", 1), guidN("b", 1)
	if c.Status.ExternalID != id || c.Status.ExternalName != name {
		t.Fatalf("status = %q %q", c.Status.ExternalID, c.Status.ExternalName)
	}
	in := f.created[0]
	if in.DisplayName != name || in.Audience != idpclient.GraphAudience || in.Public ||
		!slices.Equal(in.WebRedirectURIs, []string{"https://app.example/cb"}) || len(in.PublicRedirectURIs) != 0 || in.LogoutURL != "https://app.example/bye" {
		t.Errorf("create input = %+v", in)
	}
	if got := f.keys(id); len(got) != 1 {
		t.Errorf("secrets = %v", got)
	}
	s := o.secret("team", "web")
	base := entraAuthority + "/" + testTenant
	want := [][2]string{
		{"clientId", appID}, {"clientSecret", "secret-1"}, {"issuer", base + "/v2.0"},
		{"authorizationEndpoint", base + "/oauth2/v2.0/authorize"}, {"tokenEndpoint", base + "/oauth2/v2.0/token"},
		{"jwksUri", base + "/discovery/v2.0/keys"}, {"userinfoEndpoint", "https://graph.microsoft.com/oidc/userinfo"},
	}
	if s == nil {
		t.Fatal("no binding Secret")
	}
	for _, kv := range want {
		if got := string(s.Data[kv[0]]); got != kv[1] {
			t.Errorf("binding %s = %q, want %q", kv[0], got, kv[1])
		}
	}

	// A matching application is not written again.
	o.ok()
	if f.count("update") != 0 {
		t.Fatal("a matching application was updated")
	}

	// Drift in the redirect URIs, in the other platform and in the logout URL is
	// corrected, and the secret is kept.
	f.with(func() { f.apps[id].WebRedirectURIs = []string{"https://evil.example/cb"} })
	o.ok()
	f.with(func() { f.apps[id].PublicRedirectURIs = []string{"https://evil.example/native"} })
	o.ok()
	f.with(func() { f.apps[id].LogoutURL = "https://evil.example/out" })
	o.ok()
	f.with(func() {
		got := f.apps[id]
		if !slices.Equal(got.WebRedirectURIs, []string{"https://app.example/cb"}) || len(got.PublicRedirectURIs) != 0 ||
			got.LogoutURL != "https://app.example/bye" || f.n != 1 {
			t.Errorf("application after drift = %+v", got)
		}
	})
	if n := f.count("update"); n != 3 {
		t.Errorf("updates = %d", n)
	}
	if got := string(o.secret("team", "web").Data["clientSecret"]); got != "secret-1" {
		t.Errorf("secret after updates = %q", got)
	}

	// Deleting the claim deletes the application.
	o.del()
	o.ok()
	if !o.gone() || len(f.apps) != 0 {
		t.Errorf("claim gone = %v, applications = %d", o.gone(), len(f.apps))
	}
}

// A rotation adds a second secret and keeps the first valid through the grace
// period; when it ends every secret but the new one is removed, including the
// one Create issued, which the status never named.
func TestEntraRotationOverlapsAndFinishes(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{})
	o.ok()
	id := guidN("a", 1)

	o.rotate("1")
	o.ok()
	c := o.get()
	keys := f.keys(id)
	if len(keys) != 2 || c.Status.Rotation == nil || c.Status.Rotation.Active != keys[1] || c.Status.Rotation.RetireAfter == nil {
		t.Fatalf("keys = %v, rotation = %+v", keys, c.Status.Rotation)
	}
	if got := string(o.secret("team", "web").Data["clientSecret"]); got != "secret-2" {
		t.Errorf("rotated secret = %q", got)
	}

	o.now = o.now.Add(2 * time.Hour)
	o.ok()
	if got := f.keys(id); !slices.Equal(got, []string{keys[1]}) {
		t.Errorf("keys after the grace period = %v, want only %s", got, keys[1])
	}

	// A second rotation retires the first rotation's secret by its key ID.
	o.rotate("2")
	o.ok()
	if got := f.keys(id); len(got) != 2 {
		t.Fatalf("keys = %v", got)
	}
	o.now = o.now.Add(2 * time.Hour)
	o.ok()
	if got := f.keys(id); len(got) != 1 || got[0] == keys[1] {
		t.Errorf("keys after the second rotation = %v", got)
	}
	wantCond(t, o.get(), conditions.Synced, metav1.ConditionTrue, "")
}

// A rotation that crashed after issuing its secret and before the binding was
// written leaves a secret of the same name: the retry removes it, so none leaks.
func TestEntraRotationRetryDoesNotLeakASecret(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{})
	o.ok()
	id := guidN("a", 1)
	f.with(func() {
		f.apps[id].Passwords = append(f.apps[id].Passwords, idpclient.GraphPassword{KeyID: guidN("d", 1), DisplayName: passwordName(1)})
	})
	o.rotate("1")
	o.ok()
	for _, k := range f.keys(id) {
		if k == guidN("d", 1) {
			t.Fatalf("the leftover secret was kept: %v", f.keys(id))
		}
	}
	if len(f.keys(id)) != 2 {
		t.Errorf("keys = %v", f.keys(id))
	}
}

// A binding Secret that was deleted is written again through a rotation, since
// a secret cannot be read from Graph.
func TestEntraLostBindingIsReissued(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{})
	o.ok()
	if err := o.c.Delete(context.Background(), o.secret("team", "web")); err != nil {
		t.Fatal(err)
	}
	o.ok()
	if got := o.secret("team", "web"); got == nil || string(got.Data["clientSecret"]) != "secret-2" || f.n != 1 {
		t.Errorf("rebuilt binding = %v after %d applications", got, f.n)
	}
}

// A public client has redirect URIs on the public client platform, no secret,
// and nothing to rotate; a client_credentials client has no redirect URI, and
// web origins, which an application has no field for, are reported and dropped.
func TestEntraPublicAndClientCredentialsClients(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = true })
	o.ok()
	id := guidN("a", 1)
	in := f.created[0]
	s := o.secret("team", "web")
	if !in.Public || len(in.WebRedirectURIs) != 0 || !slices.Equal(in.PublicRedirectURIs, []string{"https://app.example/cb"}) ||
		len(f.keys(id)) != 0 || s == nil || s.Data["clientSecret"] != nil || string(s.Data["clientId"]) != guidN("b", 1) {
		t.Errorf("public client: %+v, %v", in, s)
	}
	o.ok()
	if f.count("update") != 0 {
		t.Error("a matching public client was updated")
	}
	o.rotate("1")
	o.ok()
	if f.count("add") != 0 || len(f.keys(id)) != 0 {
		t.Error("a public client was given a secret")
	}

	f = newFakeGraph()
	o = newEntraOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) {
		c.Spec.GrantTypes = []oidcv1alpha1.GrantType{oidcv1alpha1.GrantClientCredentials}
		c.Spec.RedirectURIs = nil
		c.Spec.WebOrigins = []oidcv1alpha1.WebOrigin{"https://app.example"}
	})
	o.ok()
	if in := f.created[0]; len(in.WebRedirectURIs) != 0 || len(f.keys(guidN("a", 1))) != 1 {
		t.Errorf("create input = %+v", in)
	}
	got := wantCond(t, o.get(), conditionWebOriginsIgnored, metav1.ConditionTrue, reasonWebOriginsIgnored)
	if got.Message != textWebOriginsIgnored {
		t.Errorf("message = %q", got.Message)
	}
}

// A claim that changes between public and confidential is refused with a fixed
// text and nothing is changed.
func TestEntraClientTypeCannotChange(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{})
	o.ok()
	o.edit(func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = true })
	o.failing(ErrEntraSecret.Error())
	if f.count("update") != 0 {
		t.Error("an application was updated into another type")
	}

	f = newFakeGraph()
	o = newEntraOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = true })
	o.ok()
	o.edit(func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = false })
	o.failing(ErrEntraSecret.Error())
}

// A scope that is no OIDC scope, and a second post-logout URI, are refused
// before anything is made.
func TestEntraRefusesWhatAnApplicationCannotHold(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) {
		c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "email"}
		c.Spec.PostLogoutRedirectURIs = []oidcv1alpha1.RedirectURI{"https://app.example/a", "https://app.example/b"}
	})
	o.failing(ErrEntraLogout.Error())

	o = newEntraOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) {
		c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "email"}
	})
	o.ok()

	f = newFakeGraph()
	o = newEntraOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) { c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "User.Read"} })
	o.failing("is not in the provider's allowedScopes")

	// Allowed by the provider, but no OIDC scope.
	objs := entraObjects()
	objs[2].(*oidcv1alpha1.ClusterIdentityProvider).Spec.AllowedScopes = []oidcv1alpha1.Scope{"openid", "User.Read"}
	o = newOC(t, interceptor.Funcs{}, with(objs, entraClaim(func(c *oidcv1alpha1.OidcClient) {
		c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "User.Read"}
	}))...)
	o.r.Entra = graphFactory(f)
	o.failing(ErrEntraScope.Error())
	if f.count("create") != 0 {
		t.Error("an application was made")
	}
	o.del()
	o.ok()
	if !o.gone() {
		t.Error("the claim was not deleted")
	}
}

// An application made without its secret (the call failed) gets one at the next
// reconcile.
func TestEntraMissingSecretIsIssued(t *testing.T) {
	f := newFakeGraph()
	f.failOp["add"] = graphStatus(500)
	o := newEntraOC(t, f, interceptor.Funcs{})
	o.failing("the Graph API call failed")
	if o.secret("team", "web") != nil || len(f.apps) != 1 {
		t.Fatal("unexpected state after the failed secret")
	}
	f.failOp["add"] = nil
	o.ok()
	if got := o.secret("team", "web"); got == nil || string(got.Data["clientSecret"]) != "secret-1" || f.n != 1 {
		t.Errorf("binding = %v after %d applications", got, f.n)
	}
}

// A failing API shows one fixed text per kind of failure, never its own words,
// and a throttled call says the provider is unreachable.
func TestEntraAPIFailuresAreCategories(t *testing.T) {
	f := newFakeGraph()
	f.failOp["create"] = graphStatus(400)
	o := newEntraOC(t, f, interceptor.Funcs{})
	o.failing("the provider refused the request")

	f.failOp["create"] = graphStatus(429)
	o.failing("the Graph API call failed")
	wantCond(t, o.get(), conditions.ServerReachable, metav1.ConditionFalse, conditions.ServerUnreachable)

	f.failOp["create"] = fmt.Errorf("%w: AADSTS70011 for client 0000", idpclient.ErrGraphToken)
	o.failing("the cloud credentials are unavailable")

	// A create answered with a document that has no IDs may have made an
	// application the operator cannot name: say so.
	f.failOp["create"] = nil
	f.createEmpty = true
	o.failing("the provider answered with an unexpected document")
	wantCond(t, o.get(), conditionRegistrationUnconfirmed, metav1.ConditionTrue, reasonRegistrationUnconfirmed)
}

// Observe tells an application someone deleted from one that cannot be read.
func TestEntraObserveFailures(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{})
	o.ok()
	f.with(func() { clear(f.apps) })
	o.ok()
	if c := o.get(); c.Status.ExternalID != guidN("a", 2) {
		t.Errorf("externalId = %q", c.Status.ExternalID)
	}
	f.failOp["get"] = graphStatus(400)
	o.failing("the provider refused the request")
}

// A delete the tenant refuses keeps the claim; an application that is already
// gone does not.
func TestEntraDelete(t *testing.T) {
	f := newFakeGraph()
	o := newEntraOC(t, f, interceptor.Funcs{})
	o.ok()
	o.del()
	f.failOp["delete"] = graphStatus(400)
	if _, err := o.reconcile(); err == nil || o.gone() {
		t.Fatalf("a failed delete released the claim: %v", err)
	}
	f.failOp["delete"] = nil
	f.with(func() { clear(f.apps) })
	o.ok()
	if !o.gone() {
		t.Error("an application that is already gone held the claim")
	}
}

// An application the status cannot record is taken back at once, and one that
// cannot be taken back is reported.
func TestEntraCreateTakesBackWhatItCannotRecord(t *testing.T) {
	failStatus := interceptor.Funcs{SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
		return errors.New("the API server is down")
	}}
	f := newFakeGraph()
	o := newEntraOC(t, f, failStatus)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a status that could not be written was not reported")
	}
	if len(f.apps) != 0 || f.count("delete") != 1 {
		t.Errorf("the application was not taken back: %d applications, %d deletes", len(f.apps), f.count("delete"))
	}

	f = newFakeGraph()
	f.failOp["delete"] = graphStatus(400)
	o = newEntraOC(t, f, failStatus)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a status that could not be written was not reported")
	}
	if len(f.apps) != 1 || !o.rec.has("Warning "+reasonCleanupFailed) {
		t.Errorf("%d applications, events = %v", len(f.apps), o.rec.events)
	}
}

// A provider whose credentials cannot be used is refused with a fixed text.
func TestEntraCredentialProblems(t *testing.T) {
	o := newOC(t, interceptor.Funcs{}, namespace("team"), entraProvider(), entraClaim())
	o.failing(invalidProvider)

	// A Secret without the keys, and an endpoint override the egress mode or
	// the scheme forbids, are refused when the client is built.
	o = newOC(t, interceptor.Funcs{}, namespace("team"), secret(opsNS, "azure", map[string]string{"clientId": azureKeys["clientId"]}), entraProvider(), entraClaim())
	o.failing("the cloud credentials are unavailable")
	override := entraProvider()
	override.Spec.Entra.EndpointOverride = "https://10.0.0.5:8443"
	o = newOC(t, interceptor.Funcs{}, namespace("team"), secret(opsNS, "azure", azureKeys), override, entraClaim())
	o.failing("endpointOverride is not allowed here")

	// A provider of type Entra without its block.
	broken := entraProvider()
	broken.Spec.Entra = nil
	o = newOC(t, interceptor.Funcs{}, namespace("team"), secret(opsNS, "azure", azureKeys), broken, entraClaim())
	o.failing(invalidProvider)
}

// The probe lists the applications the identity owns, records the tenant and the
// authority host in status.discovered and the derived endpoints in
// status.discovery, for both provider kinds.
func TestProbeEntra(t *testing.T) {
	ctx := context.Background()
	f := newFakeGraph()
	p := Prober{Config: Config{HostDialer: direct, Entra: graphFactory(f)}}
	cluster := entraProvider()
	ns := &oidcv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "ent"}}
	ns.Spec.ProviderConfig = cluster.Spec.ProviderConfig
	ns.Spec.Credentials = &cloud.NamespacedCredentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "azure"}}
	conn := server.CloudConnection{Credentials: map[string][]byte{"clientId": []byte(azureKeys["clientId"]), "clientSecret": []byte("x")}}

	for _, srv := range []server.CloudServer{cluster, ns} {
		res, err := p.ProbeCloud(ctx, srv, conn)
		if err != nil {
			t.Fatalf("%T: %v", srv, err)
		}
		if res.Discovered[discoveredResourceID] != testTenant || res.Discovered[discoveredEndpoint] != "login.microsoftonline.com" ||
			len(res.Discovered) != 2 {
			t.Errorf("%T discovered = %v", srv, res.Discovered)
		}
	}
	if d := cluster.Status.Discovery; d == nil || d.TokenEndpoint != entraAuthority+"/"+testTenant+"/oauth2/v2.0/token" {
		t.Errorf("discovery = %+v", d)
	}
	if f.count("probe") != 2 {
		t.Errorf("probes = %d", f.count("probe"))
	}

	// A refusal and a throttled call are categories; neither carries SDK text.
	f.failOp["probe"] = graphStatus(403)
	_, err := p.ProbeCloud(ctx, cluster, conn)
	if err == nil || strings.Contains(err.Error(), "403") {
		t.Errorf("err = %v", err)
	}
	f.failOp["probe"] = graphStatus(503)
	_, err = p.ProbeCloud(ctx, cluster, conn)
	if err == nil || err.Error() != "the Graph API call failed" {
		t.Errorf("err = %v", err)
	}
}

var _ lifecycle.Rotator[oidcv1alpha1.OidcClientSpec, clientState] = (*entraExternal)(nil)
