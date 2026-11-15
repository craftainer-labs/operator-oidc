package controller

import (
	"context"
	"errors"
	"net/url"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// foreignKind satisfies server.Server without being one of the operator's kinds.
type foreignKind struct{ *oidcv1alpha1.IdentityProvider }

func connFor(f *idp, admin map[string]string) server.Connection {
	conn := server.Connection{Endpoint: f.srv.URL, CABundle: f.ca, Admin: map[string][]byte{}}
	for k, v := range admin {
		conn.Admin[k] = []byte(v)
	}
	return conn
}

func discoveryOf(f *idp) *oidcv1alpha1.Discovery {
	return &oidcv1alpha1.Discovery{
		TokenEndpoint:         f.issuer() + "/protocol/openid-connect/token",
		AuthorizationEndpoint: f.issuer() + "/protocol/openid-connect/auth",
		JWKSURI:               f.issuer() + "/protocol/openid-connect/certs",
		UserinfoEndpoint:      f.issuer() + "/protocol/openid-connect/userinfo",
	}
}

// A healthy Keycloak is logged in to and its discovery document is recorded,
// for both provider kinds; a changed document is a change the probe helper
// cannot miss.
func TestProbeKeycloak(t *testing.T) {
	ctx := context.Background()
	f := startIDP(t)
	p := Prober{Config: Config{HostDialer: direct}}
	conn := connFor(f, adminCreds)

	ns := keycloakProvider("team", f)
	cluster := clusterKeycloak(f)
	for _, srv := range []server.Server{ns, cluster} {
		version, err := p.Probe(ctx, srv, conn)
		if err != nil || version != "" {
			t.Fatalf("%T: %q, %v", srv, version, err)
		}
	}
	if f.tokenCount() != 2 {
		t.Errorf("tokens = %d", f.tokenCount())
	}
	want := discoveryOf(f)
	for _, got := range []*oidcv1alpha1.Discovery{ns.Status.Discovery, cluster.Status.Discovery} {
		if got == nil || *got != *want {
			t.Errorf("discovery = %+v, want %+v", got, want)
		}
	}

	// The same document again changes nothing: the next write still waits for
	// the helper's own reasons.
	stamped := metav1.Now()
	ns.Status.LastProbeTime = &stamped
	if _, err := p.Probe(ctx, ns, conn); err != nil || ns.Status.LastProbeTime == nil {
		t.Errorf("an unchanged document cleared lastProbeTime: %v", err)
	}
	// A changed one clears it, so the helper writes the status.
	ns.Status.Discovery = &oidcv1alpha1.Discovery{AuthorizationEndpoint: "https://old.example/auth"}
	if _, err := p.Probe(ctx, ns, conn); err != nil || ns.Status.LastProbeTime != nil || *ns.Status.Discovery != *want {
		t.Errorf("a changed document: %+v, %v", ns.Status, err)
	}
}

// A provider of type DynamicRegistration is probed by its discovery document
// alone, and an issuer on another host is verified by its own name.
func TestProbeDynamicRegistration(t *testing.T) {
	ctx := context.Background()
	f := startIDP(t)
	other := startIDP(t)
	p := Prober{Config: Config{HostDialer: direct}}
	srv := dcrProvider("team", "https://idp.example/register")
	srv.Spec.Issuer = oidcv1alpha1.HTTPSURL(f.issuer())
	// The server name belongs to the registration endpoint's host; a certificate
	// for it must not be demanded of the issuer's host.
	conn := connFor(f, nil)
	conn.Endpoint, conn.ServerName = "https://idp.example/register", "idp.example"
	if _, err := p.Probe(ctx, srv, conn); err != nil {
		t.Fatalf("a registration endpoint on another host: %v", err)
	}
	if srv.Status.Discovery == nil || srv.Status.Discovery.TokenEndpoint == "" {
		t.Errorf("discovery = %+v", srv.Status.Discovery)
	}

	// On the same host the override applies: it is the name the certificate of
	// the endpoint carries, so a wrong one fails the handshake.
	same := keycloakProvider("team", other)
	conn = connFor(other, adminCreds)
	conn.ServerName = "wrong.example"
	_, err := p.Probe(ctx, same, conn)
	if !errors.Is(err, idpclient.ErrConnTLS) || err.Error() != "the TLS handshake with the provider failed" {
		t.Errorf("a wrong server name: %v", err)
	}
}

func TestProbeFailuresAreCategories(t *testing.T) {
	ctx := context.Background()
	f := startIDP(t)
	p := Prober{Config: Config{HostDialer: direct}}

	// A server kind this operator does not own.
	_, err := p.Probe(ctx, foreignKind{&oidcv1alpha1.IdentityProvider{}}, server.Connection{})
	if !errors.Is(err, server.ErrUnknownServerKind) || err.Error() != invalidProvider {
		t.Errorf("an unknown kind: %v", err)
	}

	// A dialer that cannot be built (a proxy the policy refuses).
	broken := Prober{Config: Config{HostDialer: func(*url.URL) (egress.DialFunc, error) { return nil, egress.ErrProxyUserinfo }}}
	if _, err := broken.Probe(ctx, keycloakProvider("team", f), connFor(f, adminCreds)); !errors.Is(err, server.ErrInvalidServer) || err.Error() != "the connection to the provider was refused by the egress policy" {
		t.Errorf("a dialer error: %v", err)
	}

	cases := map[string]struct {
		edit func(*oidcv1alpha1.IdentityProvider, *server.Connection, *idp)
		want error
		text string
	}{
		"no admin credentials": {func(_ *oidcv1alpha1.IdentityProvider, c *server.Connection, _ *idp) { c.Admin = nil },
			ErrAdminCredentials, "the admin Secret needs the keys clientId and clientSecret"},
		"a bad realm": {func(s *oidcv1alpha1.IdentityProvider, _ *server.Connection, _ *idp) { s.Spec.Keycloak.Realm = ".." },
			idpclient.ErrInvalidRealm, invalidProvider},
		"a refused login": {func(_ *oidcv1alpha1.IdentityProvider, _ *server.Connection, f *idp) { f.tokenStatus = 401 },
			idpclient.ErrConnAuth, "the provider refused the operator's credentials"},
		"an issuer that is not the provider's": {func(s *oidcv1alpha1.IdentityProvider, _ *server.Connection, f *idp) {
			s.Spec.Issuer = oidcv1alpha1.HTTPSURL(f.srv.URL + "/realms/other")
		}, idpclient.ErrNotFound, "the provider refused the request"},
		"an issuer that is not a URL": {func(s *oidcv1alpha1.IdentityProvider, _ *server.Connection, _ *idp) {
			s.Spec.Issuer = "https://%zz"
		}, idpclient.ErrInvalidEndpoint, invalidProvider},
	}
	for name, tc := range cases {
		prov := startIDP(t)
		srv := keycloakProvider("team", prov)
		conn := connFor(prov, adminCreds)
		tc.edit(srv, &conn, prov)
		_, err := p.Probe(ctx, srv, conn)
		if err == nil || err.Error() != tc.text || !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.text)
		}
		if srv.Status.Discovery != nil {
			t.Errorf("%s: a failed probe recorded discovery", name)
		}
	}
}

// The probe uses the real policy when no dialer is set: it refuses the
// loopback address and says so by category.
func TestRealPolicyRefusesLoopback(t *testing.T) {
	f := startIDP(t)
	p := Prober{Config: Config{Egress: egress.NewPolicy(egress.ModeAllowPrivate)}}
	_, err := p.Probe(context.Background(), keycloakProvider("team", f), connFor(f, adminCreds))
	if !errors.Is(err, idpclient.ErrConnPolicy) || err.Error() != "the connection to the provider was refused by the egress policy" {
		t.Errorf("err = %v", err)
	}
	if f.tokenCount() != 0 {
		t.Error("a request reached the provider")
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("https://idp.example:8443/realms/x"); got != "idp.example:8443" {
		t.Errorf("host = %q", got)
	}
	if got := hostOf("https://%zz"); got != "" {
		t.Errorf("an unparsable URL has host %q", got)
	}
}
