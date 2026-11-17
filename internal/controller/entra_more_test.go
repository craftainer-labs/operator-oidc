package controller

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// entraDrv is a driver over f with an application and one secret, and the
// state Observe would have read.
func entraDrv(t *testing.T, f *fakeGraph) (*entraDriver, entraState) {
	t.Helper()
	made, _ := f.Create(context.Background(), idpclient.GraphApp{DisplayName: "n"})
	if _, err := f.AddPassword(context.Background(), made.ID, passwordName(0)); err != nil {
		t.Fatal(err)
	}
	b := base{cfg: Config{Client: fakeClient(t)}, claim: oidcClient(), be: &Backend{}}
	b.persist = func(context.Context) error { return nil }
	b.claim.SetExternalID(made.ID)
	return &entraDriver{base: b, api: f}, entraState{ID: made.ID, AppID: made.AppID, HasSecret: true}
}

var entraW = clientSpec{redirectURIs: []string{"https://app.example/cb"}}

func TestEntraDriverUpdateFailures(t *testing.T) {
	ctx := context.Background()
	f := newFakeGraph()
	d, cur := entraDrv(t, f)
	// The secret is not readable: with no binding Secret the application gets a
	// new one, and the one nobody holds is removed.
	if data, err := d.update(ctx, entraW, cur); err != nil || string(data["clientSecret"]) != fakeSecret(2) || len(f.keys(cur.ID)) != 1 {
		t.Errorf("data = %v, err = %v, keys = %v", data, err, f.keys(cur.ID))
	}
	w := entraW
	w.postLogout = []string{"https://app.example/a", "https://app.example/b"}
	if _, err := d.update(ctx, w, cur); !errors.Is(err, ErrEntraLogout) {
		t.Errorf("err = %v", err)
	}
	// A binding Secret that cannot be read is reported.
	good := d.cfg.Client
	d.cfg.Client = fakeClientWith(t, interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
		return errors.New("the API server is down")
	}})
	if _, err := d.update(ctx, entraW, cur); err == nil || errors.Is(err, ErrBindingNotUsable) {
		t.Errorf("err = %v", err)
	}
	d.cfg.Client = good
	f.failOp["update"] = graphStatus(400)
	if _, err := d.update(ctx, entraW, cur); err == nil {
		t.Error("a refused update succeeded")
	}
	f.failOp["update"] = nil
	f.failOp["add"] = graphStatus(400)
	cur.HasSecret = false
	if _, err := d.update(ctx, entraW, cur); err == nil {
		t.Error("a refused secret succeeded")
	}
}

func TestEntraDriverRotationFailures(t *testing.T) {
	ctx := context.Background()
	st := lifecycle.RotationState{}
	f := newFakeGraph()
	d, cur := entraDrv(t, f)

	f.failOp["add"] = graphStatus(400)
	if _, _, err := d.rotateBegin(ctx, entraW, cur, st); err == nil {
		t.Error("a refused secret rotated")
	}
	f.failOp["add"] = nil
	if _, _, err := d.rotateBegin(ctx, entraW, cur, st); err != nil {
		t.Fatal(err)
	}

	// RotateFinish: a failed read, an active secret that is not there (nothing
	// is removed), a failed removal and an application that is gone.
	active := lifecycle.RotationState{Active: lifecycle.Generation(f.keys(cur.ID)[0])}
	f.failOp["get"] = graphStatus(400)
	if err := d.rotateFinish(ctx, entraW, cur, active); err == nil {
		t.Error("a failed read finished")
	}
	f.failOp["get"] = nil
	if err := d.rotateFinish(ctx, entraW, cur, lifecycle.RotationState{Active: lifecycle.Generation(guidN("e", 9))}); !errors.Is(err, ErrBindingNotUsable) {
		t.Errorf("err = %v", err)
	}
	if len(f.keys(cur.ID)) != 2 {
		t.Errorf("secrets were removed: %v", f.keys(cur.ID))
	}
	f.failOp["remove"] = graphStatus(400)
	if err := d.rotateFinish(ctx, entraW, cur, active); err == nil {
		t.Error("a failed removal finished")
	}
	f.failOp["remove"] = nil
	f.with(func() { clear(f.apps) })
	if err := d.rotateFinish(ctx, entraW, cur, active); err != nil {
		t.Errorf("an application that is gone: %v", err)
	}
}

// A claim the controller refuses (wantErr) is refused by Update and RotateBegin
// before the driver is used.
func TestEntraExternalRefusesWhatWantErrSays(t *testing.T) {
	ctx := context.Background()
	e := &entraExternal{claim: oidcClient(), wantErr: ErrEntraScope}
	if _, err := e.Update(ctx, oidcv1alpha1.OidcClientSpec{}, clientState{}); !errors.Is(err, ErrEntraScope) {
		t.Errorf("err = %v", err)
	}
	if _, _, err := e.RotateBegin(ctx, oidcv1alpha1.OidcClientSpec{}, clientState{}, lifecycle.RotationState{}); !errors.Is(err, ErrEntraScope) {
		t.Errorf("err = %v", err)
	}
}

// A factory that cannot build the client fails the claim with its text.
func TestEntraFactoryError(t *testing.T) {
	o := newOC(t, interceptor.Funcs{}, with(entraObjects(), entraClaim())...)
	o.r.Entra = func(*cloud.AzureClient) (GraphAPI, error) { return nil, cloudErr("the Graph client cannot be built") }
	o.failing("the Graph client cannot be built")
}

// The default factory builds a Graph client whose token comes from azidentity
// and whose requests dial through the policy, against a fake authority and Graph
// on one TLS server; the derived endpoints follow an endpointOverride.
func TestNewGraphAgainstAFakeAuthority(t *testing.T) {
	ctx := context.Background()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		base := srv.URL + "/" + testTenant
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
			_, _ = io.WriteString(w, `{"issuer":"`+base+`/v2.0","authorization_endpoint":"`+base+`/oauth2/v2.0/authorize","token_endpoint":"`+base+`/oauth2/v2.0/token"}`)
		case strings.HasSuffix(r.URL.Path, "/token"):
			_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600,"ext_expires_in":3600}`)
		case r.URL.Path == "/v1.0/applications" && r.Header.Get("Authorization") == "Bearer tok":
			_, _ = io.WriteString(w, `{"value":[]}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	cfg := Config{EgressMode: egress.ModeAllowPrivate, RootCAs: roots}
	en := &oidcv1alpha1.EntraConfig{AzureClusterBlock: cloud.AzureClusterBlock{AzureBlock: cloud.AzureBlock{TenantID: testTenant}, EndpointOverride: srv.URL}}
	creds := &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "azure", Namespace: opsNS}}
	conn := server.CloudConnection{Credentials: map[string][]byte{"clientId": []byte(azureKeys["clientId"]), "clientSecret": []byte("x")}}

	cl, err := cfg.newEntra(ctx, en, cloud.ScopeCluster, creds, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.CloseIdleConnections()
	if err := cl.Probe(ctx); err != nil {
		t.Errorf("probe: %v", err)
	}

	d := entraDiscovery(en)
	if d.UserinfoEndpoint != srv.URL+"/oidc/userinfo" || entraIssuer(en) != srv.URL+"/"+testTenant+"/v2.0" {
		t.Errorf("discovery = %+v, issuer = %q", d, entraIssuer(en))
	}

	// The probe of the same provider.
	ref := providerRef{spec: &oidcv1alpha1.ProviderConfig{Type: oidcv1alpha1.ProviderEntra, Entra: en}, status: &oidcv1alpha1.IdentityProviderStatus{}, scope: cloud.ScopeCluster, creds: creds}
	if got, err := cfg.discoverEntra(ctx, ref, conn); err != nil || got[discoveredResourceID] != testTenant {
		t.Errorf("discovered = %v, %v", got, err)
	}
	// No block, and credentials that cannot be used, are refused.
	if _, err := cfg.discoverEntra(ctx, providerRef{spec: &oidcv1alpha1.ProviderConfig{}}, conn); err == nil {
		t.Error("a provider with no block was probed")
	}
	if _, err := cfg.discoverEntra(ctx, ref, server.CloudConnection{}); err == nil {
		t.Error("a probe without credentials succeeded")
	}

	// A client that is not an *http.Client, and an endpoint that is no URL, are refused.
	az, err := cloud.Egress{Mode: egress.ModeAllowPrivate, RootCAs: roots}.Azure(ctx, cloud.ScopeCluster, en.AzureClusterBlock, creds, conn.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	bad := *az
	bad.Endpoint = "ftp://x"
	if _, err := NewGraph(&bad); err == nil {
		t.Error("a bad endpoint was accepted")
	}
	if _, err := NewGraph(&cloud.AzureClient{}); err == nil {
		t.Error("a client with no HTTP client was accepted")
	}
}

// holdBinding makes the binding Secret of the driver's claim hold text.
func holdBinding(t *testing.T, d *entraDriver, text string) {
	t.Helper()
	s := secret(d.claim.Namespace, d.claim.GetBindingSecretName(), map[string]string{"clientSecret": text})
	s.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(d.claim, oidcv1alpha1.GroupVersion.WithKind("OidcClient"))}
	d.cfg.Client = fakeClient(t, s)
}

// A rotation whose secret never reached the binding Secret (the add succeeded,
// the binding write failed) leaves a secret of the same name; the retry adds its
// own first and then removes that one, since the binding does not hold it.
func TestEntraRotateBeginRemovesWhatAFailedAttemptLeft(t *testing.T) {
	ctx := context.Background()
	f := newFakeGraph()
	d, cur := entraDrv(t, f)
	holdBinding(t, d, fakeSecret(1))
	st := lifecycle.RotationState{}

	_, lost, err := d.rotateBegin(ctx, entraW, cur, st)
	if err != nil {
		t.Fatal(err)
	}
	data, kept, err := d.rotateBegin(ctx, entraW, cur, st)
	if err != nil {
		t.Fatal(err)
	}
	keys := f.keys(cur.ID)
	if slices.Contains(keys, string(lost)) || !slices.Contains(keys, string(kept)) || len(keys) != 2 {
		t.Errorf("keys = %v, lost = %s, kept = %s", keys, lost, kept)
	}
	if string(data["clientSecret"]) != fakeSecret(3) {
		t.Errorf("the binding data holds %q", data["clientSecret"])
	}
	// The secret the binding holds was never removed.
	if !slices.Contains(keys, guidN("c", 1)) {
		t.Errorf("the binding's secret is gone: %v", keys)
	}
}

// A rotation whose binding was written but whose status mark failed leaves a
// secret the binding holds: the retry keeps it, so the binding stays valid until
// it is written again, and the next retry removes it once it is not the binding's.
func TestEntraRotateBeginKeepsTheSecretTheBindingHolds(t *testing.T) {
	ctx := context.Background()
	f := newFakeGraph()
	d, cur := entraDrv(t, f)
	st := lifecycle.RotationState{}

	_, first, err := d.rotateBegin(ctx, entraW, cur, st)
	if err != nil {
		t.Fatal(err)
	}
	holdBinding(t, d, fakeSecret(2))
	_, second, err := d.rotateBegin(ctx, entraW, cur, st)
	if err != nil {
		t.Fatal(err)
	}
	keys := f.keys(cur.ID)
	if !slices.Contains(keys, string(first)) || !slices.Contains(keys, string(second)) || len(keys) != 3 {
		t.Errorf("the binding's secret was removed: keys = %v", keys)
	}

	holdBinding(t, d, fakeSecret(3))
	_, third, err := d.rotateBegin(ctx, entraW, cur, st)
	if err != nil {
		t.Fatal(err)
	}
	keys = f.keys(cur.ID)
	if slices.Contains(keys, string(first)) || !slices.Contains(keys, string(second)) || !slices.Contains(keys, string(third)) || len(keys) != 3 {
		t.Errorf("keys = %v", keys)
	}
}

// However often a rotation is retried, the application holds at most the secret
// it had, the one the binding holds and the new one.
func TestEntraRotateBeginKeepsTheCountBounded(t *testing.T) {
	ctx := context.Background()
	f := newFakeGraph()
	d, cur := entraDrv(t, f)
	holdBinding(t, d, fakeSecret(1))
	for range 8 {
		if _, _, err := d.rotateBegin(ctx, entraW, cur, lifecycle.RotationState{}); err != nil {
			t.Fatal(err)
		}
		if n := len(f.keys(cur.ID)); n != 2 {
			t.Fatalf("secrets = %d", n)
		}
	}
	// A clean-up that fails loses nothing: the new secret is still returned.
	f.failOp["get"] = graphStatus(500)
	if data, _, err := d.rotateBegin(ctx, entraW, cur, lifecycle.RotationState{}); err != nil || len(data["clientSecret"]) == 0 {
		t.Errorf("data = %v, err = %v", data, err)
	}
	f.failOp["get"] = nil
	f.failOp["remove"] = graphStatus(500)
	if data, _, err := d.rotateBegin(ctx, entraW, cur, lifecycle.RotationState{}); err != nil || len(data["clientSecret"]) == 0 {
		t.Errorf("data = %v, err = %v", data, err)
	}
}

// RotateFinish keeps the secret the binding holds even when it is not the
// active generation (one issued for a binding that had none during a rotation).
func TestEntraRotateFinishKeepsTheBindingsSecret(t *testing.T) {
	ctx := context.Background()
	f := newFakeGraph()
	d, cur := entraDrv(t, f)
	if _, err := f.AddPassword(ctx, cur.ID, passwordName(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AddPassword(ctx, cur.ID, passwordName(2)); err != nil {
		t.Fatal(err)
	}
	holdBinding(t, d, fakeSecret(1))
	active := lifecycle.RotationState{Active: lifecycle.Generation(guidN("c", 3))}
	if err := d.rotateFinish(ctx, entraW, cur, active); err != nil {
		t.Fatal(err)
	}
	if got := f.keys(cur.ID); !slices.Equal(got, []string{guidN("c", 1), guidN("c", 3)}) {
		t.Errorf("keys = %v", got)
	}
}

// A confidential application whose binding Secret holds a secret the application
// no longer has gets a new one, as one whose binding is missing does; a binding
// that holds one of its secrets is kept as it is.
func TestEntraUpdateIssuesASecretOnlyWhenTheBindingHasNoneUsable(t *testing.T) {
	ctx := context.Background()
	f := newFakeGraph()
	d, cur := entraDrv(t, f)
	holdBinding(t, d, fakeSecret(1))
	if data, err := d.update(ctx, entraW, cur); err != nil || string(data["clientSecret"]) != fakeSecret(1) || f.count("add") != 1 {
		t.Errorf("data = %v, err = %v, adds = %d", data, err, f.count("add"))
	}
	holdBinding(t, d, "zzz-gone")
	if data, err := d.update(ctx, entraW, cur); err != nil || string(data["clientSecret"]) != fakeSecret(2) {
		t.Errorf("data = %v, err = %v", data, err)
	}
}

// A token that cannot be fetched is a category: the egress policy's refusal and
// a refusal of the credentials do not pass; a deadline, a network error and a
// 5xx or 429 answer of the authority do. None carries the cause's text.
func TestEntraTokenErrorsAreClassified(t *testing.T) {
	tok := func(cause error) error { return entraErr(fmt.Errorf("%w: %w", idpclient.ErrGraphToken, cause)) }
	answered := func(status int) error {
		return &azidentity.AuthenticationFailedError{RawResponse: &http.Response{StatusCode: status}}
	}
	for name, tc := range map[string]struct {
		cause     error
		transient bool
		text      string
	}{
		"refused":   {answered(401), false, "the cloud credentials are unavailable"},
		"bad":       {answered(400), false, "the cloud credentials are unavailable"},
		"5xx":       {answered(503), true, "the Entra authority call failed"},
		"throttled": {answered(429), true, "the Entra authority call failed"},
		"deadline":  {context.DeadlineExceeded, true, "the Entra authority call failed"},
		"egress":    {fmt.Errorf("dial: %w", egress.ErrBlocked), false, "the connection to the Entra authority was refused by the egress policy"},
		"unknown":   {errors.New("AADSTS70011 for client 0000"), false, "the cloud credentials are unavailable"},
	} {
		err := tok(tc.cause)
		if err.Error() != tc.text || errors.Is(err, lifecycle.ErrUnreachable) != tc.transient {
			t.Errorf("%s: err = %v, transient = %v", name, err, errors.Is(err, lifecycle.ErrUnreachable))
		}
	}
}

// An endpoint that is no https URL without a query or fragment is refused
// before any request, with the text that says what is allowed.
func TestNewGraphRefusesEndpointsThatAreNotPlainHTTPS(t *testing.T) {
	ctx := context.Background()
	roots := x509.NewCertPool()
	creds := &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "azure", Namespace: opsNS}}
	conn := server.CloudConnection{Credentials: map[string][]byte{"clientId": []byte(azureKeys["clientId"]), "clientSecret": []byte("x")}}
	en := &oidcv1alpha1.EntraConfig{AzureClusterBlock: cloud.AzureClusterBlock{AzureBlock: cloud.AzureBlock{TenantID: testTenant}, EndpointOverride: "https://10.0.0.5:8443"}}
	az, err := cloud.Egress{Mode: egress.ModeAllowPrivate, RootCAs: roots}.Azure(ctx, cloud.ScopeCluster, en.AzureClusterBlock, creds, conn.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://10.0.0.5", "https://10.0.0.5/?a=b", "https://10.0.0.5/#f", "https://u:p@10.0.0.5", "https://10.0.0.5/?"} {
		a := *az
		a.Endpoint = bad
		_, err := NewGraph(&a)
		if err == nil || err.Error() != textEntraEndpoint {
			t.Errorf("NewGraph(%q) = %v", bad, err)
		}
	}
}
