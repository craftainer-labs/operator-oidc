package controller

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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
	// The secret is not readable: with no binding Secret there is nothing to return.
	if _, err := d.update(ctx, entraW, cur); !errors.Is(err, ErrBindingNotUsable) {
		t.Errorf("err = %v", err)
	}
	w := entraW
	w.postLogout = []string{"https://app.example/a", "https://app.example/b"}
	if _, err := d.update(ctx, w, cur); !errors.Is(err, ErrEntraLogout) {
		t.Errorf("err = %v", err)
	}
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

	f.failOp["get"] = graphStatus(400)
	if _, _, err := d.rotateBegin(ctx, entraW, cur, st); err == nil {
		t.Error("a failed read rotated")
	}
	f.failOp["get"] = nil
	f.failOp["add"] = graphStatus(400)
	if _, _, err := d.rotateBegin(ctx, entraW, cur, st); err == nil {
		t.Error("a refused secret rotated")
	}
	f.failOp["add"] = nil
	f.with(func() {
		f.apps[cur.ID].Passwords = append(f.apps[cur.ID].Passwords, idpclient.GraphPassword{KeyID: guidN("d", 1), DisplayName: passwordName(1)})
	})
	f.failOp["remove"] = graphStatus(400)
	if _, _, err := d.rotateBegin(ctx, entraW, cur, st); err == nil {
		t.Error("a leftover that could not be removed rotated")
	}
	f.failOp["remove"] = nil

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
