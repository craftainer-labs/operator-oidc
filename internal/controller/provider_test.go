package controller

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

var adminCreds = map[string]string{"clientId": "operator", "clientSecret": "s3cret"}

func config(c client.Client) Config {
	return Config{Client: c, OperatorNamespace: opsNS, HostDialer: direct, Cache: NewProviderCache(time.Hour)}
}

// A namespaced provider's client is made once, kept between reconciles, works
// against the provider and is replaced when the admin credentials change.
func TestBackendKeycloakIsCachedAndReplacedWithItsCredentials(t *testing.T) {
	ctx := context.Background()
	f := startIdP(t)
	c := fakeClient(t, namespace("team"), secret("team", "admin", adminCreds), caConfigMap("team", f), keycloakProvider("team", f))
	cfg := config(c)
	kc := ref(kindIdentityProvider, "kc")

	use := func() *idpclient.Keycloak {
		t.Helper()
		b, err := cfg.Backend(ctx, "team", kc)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Release()
		if b.Spec.Type != oidcv1alpha1.ProviderKeycloak || b.Conn.Endpoint != f.srv.URL {
			t.Errorf("backend = %+v", b)
		}
		k, err := b.Keycloak()
		if err != nil {
			t.Fatal(err)
		}
		if err := k.Probe(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := b.DCR(); !errors.Is(err, server.ErrInvalidServer) {
			t.Errorf("a Keycloak provider gave a DCR client: %v", err)
		}
		return k
	}
	k1 := use()
	if k2 := use(); k2 != k1 || cfg.Cache.Len() != 1 || f.tokenCount() != 1 {
		t.Errorf("the client was not reused (tokens = %d, entries = %d)", f.tokenCount(), cfg.Cache.Len())
	}

	// A rotated admin secret makes a new client, which logs in again.
	s := secret("team", "admin", map[string]string{"clientId": "operator", "clientSecret": "rotated"})
	if err := c.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	if k3 := use(); k3 == k1 || f.tokenCount() != 2 {
		t.Errorf("the client survived a rotation (tokens = %d)", f.tokenCount())
	}
}

// A cluster provider is one client for every namespace it admits, and its
// admin Secret is the operator namespace's.
func TestBackendClusterProvider(t *testing.T) {
	ctx := context.Background()
	f := startIdP(t)
	closed := clusterKeycloak(f)
	closed.Name = "closed"
	closed.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesSelector}
	c := fakeClient(t, namespace("team"), namespace("other"), secret(opsNS, "admin", adminCreds), caConfigMap(opsNS, f),
		clusterKeycloak(f), closed)
	cfg := config(c)

	get := func(ns, name string) (*idpclient.Keycloak, error) {
		b, err := cfg.Backend(ctx, ns, ref(kindClusterIdentityProvider, name))
		if err != nil {
			return nil, err
		}
		defer b.Release()
		return b.Keycloak()
	}
	k1, err := get("team", "kc")
	if err != nil {
		t.Fatal(err)
	}
	if k2, err := get("other", "kc"); err != nil || k2 != k1 || cfg.Cache.Len() != 1 {
		t.Errorf("two namespaces, two clients: %v (entries = %d)", err, cfg.Cache.Len())
	}
	_, err = get("team", "closed")
	if !errors.Is(err, server.ErrNamespaceNotAllowed) || err.Error() != "the claim's namespace is not allowed by the provider" {
		t.Errorf("a namespace the provider does not serve: %v", err)
	}
	if cfg.Cache.Len() != 1 {
		t.Errorf("a refused namespace dropped the entry of the others (entries = %d)", cfg.Cache.Len())
	}
}

func TestBackendDynamicRegistration(t *testing.T) {
	ctx := context.Background()
	const endpoint = "https://idp.example/register"
	withToken := func(p *oidcv1alpha1.IdentityProvider) *oidcv1alpha1.IdentityProvider {
		p.Spec.DynamicRegistration.InitialAccessTokenSecretRef = &oidcv1alpha1.SecretKeyRef{Name: "iat", Key: "token"}
		return p
	}
	cluster := &oidcv1alpha1.ClusterIdentityProvider{}
	cluster.Name, cluster.UID, cluster.Generation = "dcr", "uid-cdcr", 1
	cluster.Spec.ProviderConfig = withToken(dcrProvider("", endpoint)).Spec.ProviderConfig
	cluster.Spec.AdminCredentialsSecretRef = common.AdminSecretRef{Name: "admin", Namespace: opsNS}
	cluster.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesAll}
	c := fakeClient(t, namespace("team"),
		secret("team", "admin", nil), secret("team", "iat", map[string]string{"token": "tok"}),
		secret(opsNS, "admin", nil), secret(opsNS, "iat", map[string]string{"token": "cluster-tok"}),
		withToken(dcrProvider("team", endpoint)), cluster)
	cfg := config(c)

	for _, tc := range []struct{ ns, kind string }{{"team", kindIdentityProvider}, {"team", kindClusterIdentityProvider}} {
		b, err := cfg.Backend(ctx, tc.ns, ref(tc.kind, "dcr"))
		if err != nil {
			t.Fatalf("%s: %v", tc.kind, err)
		}
		d, err := b.DCR()
		if err != nil || d == nil {
			t.Errorf("%s: %v", tc.kind, err)
		}
		if _, err := b.Keycloak(); !errors.Is(err, server.ErrInvalidServer) {
			t.Errorf("%s: a DCR provider gave a Keycloak client: %v", tc.kind, err)
		}
		b.Release()
	}
	if cfg.Cache.Len() != 2 {
		t.Errorf("entries = %d", cfg.Cache.Len())
	}

	// A provider that registers without an initial access token needs no Secret.
	open := fakeClient(t, secret("team", "admin", nil), dcrProvider("team", endpoint))
	b, err := config(open).Backend(ctx, "team", ref(kindIdentityProvider, "dcr"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.DCR(); err != nil {
		t.Error(err)
	}
	b.Release()
}

// What cannot be resolved is refused with one fixed text, and a provider that
// is gone or unusable drops its cached client.
func TestBackendRefusals(t *testing.T) {
	ctx := context.Background()
	f := startIdP(t)
	base := func() []client.Object {
		return []client.Object{namespace("team"), secret("team", "admin", adminCreds), caConfigMap("team", f)}
	}
	with := func(p *oidcv1alpha1.IdentityProvider) client.Client { return fakeClient(t, append(base(), p)...) }
	mutate := func(edit func(*oidcv1alpha1.IdentityProvider)) client.Client {
		p := keycloakProvider("team", f)
		edit(p)
		return with(p)
	}

	cases := []struct {
		name string
		c    client.Client
		ref  common.ServerRef
		want error
		text string
		// drops says the cached client of the provider is dropped.
		drops bool
	}{
		{"missing provider", fakeClient(t, base()...), ref(kindIdentityProvider, "kc"), server.ErrServerNotFound, "the referenced provider was not found", true},
		{"a key the admin Secret lacks", mutate(func(p *oidcv1alpha1.IdentityProvider) {
			p.Spec.AdminCredentialsSecretRef.Key = "nokey"
		}), ref(kindIdentityProvider, "kc"), server.ErrInvalidServer, invalidProvider, true},
		{"no client secret", fakeClient(t, namespace("team"), secret("team", "admin", map[string]string{"clientId": "x"}),
			caConfigMap("team", f), keycloakProvider("team", f)), ref(kindIdentityProvider, "kc"), ErrAdminCredentials,
			"the admin Secret needs the keys clientId and clientSecret", false},
		{"no keycloak block", mutate(func(p *oidcv1alpha1.IdentityProvider) { p.Spec.Keycloak = nil }),
			ref(kindIdentityProvider, "kc"), server.ErrInvalidServer, invalidProvider, false},
		{"an unknown type", mutate(func(p *oidcv1alpha1.IdentityProvider) { p.Spec.Type = "Bogus" }),
			ref(kindIdentityProvider, "kc"), server.ErrInvalidServer, invalidProvider, false},
		{"no dynamicRegistration block", mutate(func(p *oidcv1alpha1.IdentityProvider) {
			p.Spec.Type, p.Spec.Keycloak = oidcv1alpha1.ProviderDynamicRegistration, nil
		}), ref(kindIdentityProvider, "kc"), server.ErrInvalidServer, invalidProvider, false},
		{"a missing token Secret", mutate(func(p *oidcv1alpha1.IdentityProvider) {
			p.Spec.Type, p.Spec.Keycloak = oidcv1alpha1.ProviderDynamicRegistration, nil
			p.Spec.DynamicRegistration = &oidcv1alpha1.DynamicRegistrationConfig{
				RegistrationEndpoint:        "https://idp.example/register",
				InitialAccessTokenSecretRef: &oidcv1alpha1.SecretKeyRef{Name: "gone", Key: "token"},
			}
		}), ref(kindIdentityProvider, "kc"), apierrors.NewNotFound(schema.GroupResource{}, "gone"), defaultText, false},
		{"an empty token", mutate(func(p *oidcv1alpha1.IdentityProvider) {
			p.Spec.Type, p.Spec.Keycloak = oidcv1alpha1.ProviderDynamicRegistration, nil
			p.Spec.DynamicRegistration = &oidcv1alpha1.DynamicRegistrationConfig{
				RegistrationEndpoint:        "https://idp.example/register",
				InitialAccessTokenSecretRef: &oidcv1alpha1.SecretKeyRef{Name: "admin", Key: "token"},
			}
		}), ref(kindIdentityProvider, "kc"), ErrInitialAccessToken, "initialAccessTokenSecretRef names no token", false},
	}
	for _, tc := range cases {
		cfg := config(tc.c)
		key := providerKey("team", tc.ref)
		// A cached client of the provider, to see whether it is dropped.
		_, release, err := cfg.Cache.Get(key, "old", buildMem)
		if err != nil {
			t.Fatal(err)
		}
		release()
		_, err = cfg.Backend(ctx, "team", tc.ref)
		if err == nil || err.Error() != tc.text {
			t.Errorf("%s: err = %v, want the text %q", tc.name, err, tc.text)
			continue
		}
		if !errors.Is(err, tc.want) && !isNotFound(err, tc.want) {
			t.Errorf("%s: the kind %v is not reachable in %v", tc.name, tc.want, err)
		}
		if dropped := cfg.Cache.Len() == 0; dropped != tc.drops {
			t.Errorf("%s: cached client dropped = %v, want %v", tc.name, dropped, tc.drops)
		}
	}
}

func isNotFound(err, want error) bool {
	return apierrors.IsNotFound(want) && apierrors.IsNotFound(err)
}

// A client that cannot be built is refused when it is asked for, with the
// category and nothing of the URL.
func TestBackendClientsThatCannotBeBuilt(t *testing.T) {
	ctx := context.Background()
	f := startIdP(t)
	badRealm := keycloakProvider("team", f)
	badRealm.Spec.Keycloak.Realm = ".."
	plain := dcrProvider("team", "http://idp.example/register")
	c := fakeClient(t, namespace("team"), secret("team", "admin", adminCreds), caConfigMap("team", f), badRealm, plain)
	cfg := config(c)

	b, err := cfg.Backend(ctx, "team", ref(kindIdentityProvider, "kc"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Keycloak(); !errors.Is(err, idpclient.ErrInvalidRealm) || err.Error() != invalidProvider {
		t.Errorf("a bad realm: %v", err)
	}
	b.Release()
	b, err = cfg.Backend(ctx, "team", ref(kindIdentityProvider, "dcr"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.DCR(); !errors.Is(err, idpclient.ErrInvalidEndpoint) || err.Error() != invalidProvider {
		t.Errorf("an http endpoint: %v", err)
	}
	b.Release()
	if cfg.Cache.Len() != 0 {
		t.Errorf("a failed build was cached")
	}
}

// The provider is read twice (the connection settings, then its own fields); a
// failure of the second read is refused with the default text, and so is a
// dialer that cannot be built.
func TestBackendAPIFailures(t *testing.T) {
	ctx := context.Background()
	f := startIdP(t)
	objs := []client.Object{namespace("team"), secret("team", "admin", adminCreds), caConfigMap("team", f), keycloakProvider("team", f)}
	kc := ref(kindIdentityProvider, "kc")

	boom := errors.New("boom https://leak.example")
	reads := 0
	c := fakeClientWith(t, interceptor.Funcs{Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if _, ok := obj.(*oidcv1alpha1.IdentityProvider); ok {
			if reads++; reads == 2 {
				return boom
			}
		}
		return cl.Get(ctx, key, obj, opts...)
	}}, objs...)
	_, err := config(c).Backend(ctx, "team", kc)
	if !errors.Is(err, boom) || err.Error() != defaultText {
		t.Errorf("second read: %v", err)
	}

	cfg := config(fakeClient(t, objs...))
	cfg.HostDialer = func(*url.URL) (egress.DialFunc, error) { return nil, errors.New("no dialer") }
	if _, err := cfg.Backend(ctx, "team", kc); !errors.Is(err, server.ErrInvalidServer) || err.Error() != invalidProvider {
		t.Errorf("dialer: %v", err)
	}
}

// Without a test dialer the real policy applies: it refuses the loopback
// address the fake listens on, and a nil cache closes the client on release.
func TestBackendUsesTheEgressPolicy(t *testing.T) {
	ctx := context.Background()
	f := startIdP(t)
	p := keycloakProvider("team", f)
	p.Spec.ProxyURL = "http://127.0.0.1:3128"
	c := fakeClient(t, namespace("team"), secret("team", "admin", adminCreds), caConfigMap("team", f), p)
	cfg := Config{Client: c, OperatorNamespace: opsNS, Egress: egress.NewPolicy(egress.ModeStrict)}

	b, err := cfg.Backend(ctx, "team", ref(kindIdentityProvider, "kc"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	k, err := b.Keycloak()
	if err != nil {
		t.Fatal(err)
	}
	// The proxy is dialed through the same policy: the request is not made.
	if err := k.Probe(ctx); !errors.Is(err, idpclient.ErrConnPolicy) || f.tokenCount() != 0 {
		t.Errorf("the request went out: %v (tokens = %d)", err, f.tokenCount())
	}
}

func TestStampSeparatesItsParts(t *testing.T) {
	o := providerObject{uid: "u", generation: 1}
	conn := server.Connection{Endpoint: "e"}
	if stamp(o, conn, "ab", "c") == stamp(o, conn, "a", "bc") {
		t.Error("the parts run together")
	}
	if stamp(o, conn, "a") == stamp(providerObject{uid: "u", generation: 2}, conn, "a") {
		t.Error("the generation is not in the stamp")
	}
	px, _ := url.Parse("http://proxy.example:3128")
	if stamp(o, conn) == stamp(o, server.Connection{Endpoint: "e", Proxy: px}) {
		t.Error("the proxy is not in the stamp")
	}
}
