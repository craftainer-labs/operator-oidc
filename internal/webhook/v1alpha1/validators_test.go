package v1alpha1

import (
	"context"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
)

// providerConfig is a valid Keycloak configuration with the given values.
func providerConfig(issuer, baseURL string) oidcv1alpha1.ProviderConfig {
	return oidcv1alpha1.ProviderConfig{
		Type:     oidcv1alpha1.ProviderKeycloak,
		Issuer:   oidcv1alpha1.HTTPSURL(issuer),
		Keycloak: &oidcv1alpha1.KeycloakConfig{BaseURL: oidcv1alpha1.HTTPSURL(baseURL), Realm: "craftainer"},
	}
}

func identityProvider(cfg oidcv1alpha1.ProviderConfig, proxy string) *oidcv1alpha1.IdentityProvider {
	return &oidcv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak", Namespace: "default"},
		Spec: oidcv1alpha1.IdentityProviderSpec{
			ServerCommon:   common.ServerCommon{ProxyURL: proxy},
			ProviderConfig: cfg,
		},
	}
}

func clusterIdentityProvider(cfg oidcv1alpha1.ProviderConfig, proxy string) *oidcv1alpha1.ClusterIdentityProvider {
	return &oidcv1alpha1.ClusterIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak"},
		Spec: oidcv1alpha1.ClusterIdentityProviderSpec{
			ServerCommon:   common.ServerCommon{ProxyURL: proxy},
			ProviderConfig: cfg,
		},
	}
}

func dynamicConfig(issuer, endpoint string) oidcv1alpha1.ProviderConfig {
	return oidcv1alpha1.ProviderConfig{
		Type:                oidcv1alpha1.ProviderDynamicRegistration,
		Issuer:              oidcv1alpha1.HTTPSURL(issuer),
		DynamicRegistration: &oidcv1alpha1.DynamicRegistrationConfig{RegistrationEndpoint: oidcv1alpha1.HTTPSURL(endpoint)},
	}
}

const (
	goodIssuer = "https://sso.example.com/realms/craftainer"
	goodBase   = "https://sso.example.com"
)

// providerCases are the URL and proxy rules, shared by both provider kinds.
var providerCases = []struct {
	name    string
	cfg     oidcv1alpha1.ProviderConfig
	proxy   string
	field   string // the field the error names; empty means valid
	message string // a substring of the error
}{
	{name: "valid", cfg: providerConfig(goodIssuer, goodBase)},
	{name: "valid with a port", cfg: providerConfig("https://sso.example.com:8443/realms/x", "https://sso.example.com:8443")},
	{name: "valid IPv6", cfg: providerConfig("https://[fd00::7]/realms/x", "https://[fd00::7]")},
	{name: "valid dynamic registration", cfg: dynamicConfig("https://idp.example.com", "https://idp.example.com/register")},
	{name: "valid with a proxy", cfg: providerConfig(goodIssuer, goodBase), proxy: "socks5://proxy:1080"},
	{name: "issuer over http", cfg: providerConfig("http://sso.example.com/realms/x", goodBase), field: "spec.issuer", message: "https URL"},
	{name: "issuer without a host", cfg: providerConfig("https:///realms/x", goodBase), field: "spec.issuer", message: "absolute URL with a host"},
	{name: "issuer with userinfo", cfg: providerConfig("https://user:hunter2@sso.example.com/x", goodBase), field: "spec.issuer", message: "must not carry credentials"},
	{name: "issuer with a query", cfg: providerConfig("https://sso.example.com/x?a=b", goodBase), field: "spec.issuer", message: "query or a fragment"},
	{name: "issuer with a fragment", cfg: providerConfig("https://sso.example.com/x#f", goodBase), field: "spec.issuer", message: "query or a fragment"},
	{name: "issuer with a bad host", cfg: providerConfig("https://sso_1.example.com/x", goodBase), field: "spec.issuer", message: "host name or an IP address"},
	{name: "issuer with a bad port", cfg: providerConfig("https://sso.example.com:70000/x", goodBase), field: "spec.issuer", message: "port must be between 1 and 65535"},
	{name: "issuer with a space", cfg: providerConfig("https://sso.example.com/a b", goodBase), field: "spec.issuer", message: "printable ASCII"},
	{name: "issuer with a wildcard", cfg: providerConfig("https://*.example.com", goodBase), field: "spec.issuer", message: "wildcards"},
	{name: "empty issuer", cfg: providerConfig("", goodBase), field: "spec.issuer", message: "between 1 and 2048"},
	{name: "base URL over http", cfg: providerConfig(goodIssuer, "http://sso.example.com"), field: "spec.keycloak.baseURL", message: "https URL"},
	{name: "base URL with userinfo", cfg: providerConfig(goodIssuer, "https://user@sso.example.com"), field: "spec.keycloak.baseURL", message: "must not carry credentials"},
	{name: "registration endpoint over http", cfg: dynamicConfig("https://idp.example.com", "http://idp.example.com/register"), field: "spec.dynamicRegistration.registrationEndpoint", message: "https URL"},
	{name: "registration endpoint with a fragment", cfg: dynamicConfig("https://idp.example.com", "https://idp.example.com/register#x"), field: "spec.dynamicRegistration.registrationEndpoint", message: "query or a fragment"},
	{name: "proxy with another scheme", cfg: providerConfig(goodIssuer, goodBase), proxy: "ftp://proxy", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "proxy without a host", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "malformed proxy", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://[::1", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "proxy with a user", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://user@proxy:3128", field: "spec.proxyURL", message: "must not carry credentials"},
	{name: "proxy with a password", cfg: providerConfig(goodIssuer, goodBase), proxy: "socks5://user:hunter2@proxy:1080", field: "spec.proxyURL", message: "must not carry credentials"},
	{name: "proxy with a space", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://proxy:3128/a b", field: "spec.proxyURL", message: "printable ASCII"},
	{name: "proxy with a query", cfg: providerConfig(goodIssuer, goodBase), proxy: "socks5://proxy:1080?x=y", field: "spec.proxyURL", message: "query or a fragment"},
	{name: "proxy with a fragment", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://proxy:3128#x", field: "spec.proxyURL", message: "query or a fragment"},
	{name: "proxy with a trailing colon", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://proxy:", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "proxy with an opaque form", cfg: providerConfig(goodIssuer, goodBase), proxy: "http:proxy", field: "spec.proxyURL", message: "http, https or socks5"},
	{name: "proxy with credentials names the limit", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://user@proxy:3128", field: "spec.proxyURL", message: "proxy credentials are not supported"},
	{name: "valid proxy with an underscore", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://egress_proxy:3128"},
	{name: "proxy that is too long", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://proxy/" + strings.Repeat("a", 2100), field: "spec.proxyURL", message: "between 1 and 2048"},
	{name: "valid proxy port bounds", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://proxy:65535"},
	{name: "proxy port too high", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://proxy:65536", field: "spec.proxyURL", message: "port must be between 1 and 65535"},
	{name: "proxy port zero", cfg: providerConfig(goodIssuer, goodBase), proxy: "http://proxy:0", field: "spec.proxyURL", message: "port must be between 1 and 65535"},
}

func expectField(g *WithT, err error, field, message string) {
	if field == "" {
		g.Expect(err).NotTo(HaveOccurred())
		return
	}
	g.Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
	g.Expect(err.Error()).To(ContainSubstring(field))
	g.Expect(err.Error()).To(ContainSubstring(message))
}

func TestIdentityProviderValidator(t *testing.T) {
	v := &IdentityProviderValidator{}
	ctx := context.Background()
	for _, tc := range providerCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			warnings, err := v.ValidateCreate(ctx, identityProvider(tc.cfg, tc.proxy))
			g.Expect(warnings).To(BeEmpty())
			expectField(g, err, tc.field, tc.message)

			_, err = v.ValidateUpdate(ctx, identityProvider(providerConfig(goodIssuer, goodBase), ""), identityProvider(tc.cfg, tc.proxy))
			expectField(g, err, tc.field, tc.message)
		})
	}

	g := NewWithT(t)
	// An object being deleted is admitted while its spec is unchanged, so
	// finalizer removal is never blocked; a spec change is still validated.
	bad := providerConfig("http://bad", goodBase)
	deleting := identityProvider(bad, "ftp://bad")
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	_, err := v.ValidateUpdate(ctx, identityProvider(bad, "ftp://bad"), deleting)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = v.ValidateUpdate(ctx, identityProvider(providerConfig(goodIssuer, goodBase), ""), deleting)
	g.Expect(err).To(HaveOccurred())
	_, err = v.ValidateDelete(ctx, identityProvider(bad, ""))
	g.Expect(err).NotTo(HaveOccurred())
}

func TestClusterIdentityProviderValidator(t *testing.T) {
	v := &ClusterIdentityProviderValidator{}
	ctx := context.Background()
	for _, tc := range providerCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			warnings, err := v.ValidateCreate(ctx, clusterIdentityProvider(tc.cfg, tc.proxy))
			g.Expect(warnings).To(BeEmpty())
			expectField(g, err, tc.field, tc.message)

			_, err = v.ValidateUpdate(ctx, clusterIdentityProvider(providerConfig(goodIssuer, goodBase), ""), clusterIdentityProvider(tc.cfg, tc.proxy))
			expectField(g, err, tc.field, tc.message)
		})
	}

	g := NewWithT(t)
	bad := providerConfig("http://bad", goodBase)
	deleting := clusterIdentityProvider(bad, "ftp://bad")
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	_, err := v.ValidateUpdate(ctx, clusterIdentityProvider(bad, "ftp://bad"), deleting)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = v.ValidateUpdate(ctx, clusterIdentityProvider(providerConfig(goodIssuer, goodBase), ""), deleting)
	g.Expect(err).To(HaveOccurred())
	_, err = v.ValidateDelete(ctx, clusterIdentityProvider(bad, ""))
	g.Expect(err).NotTo(HaveOccurred())
}

// An admission error never echoes a URL: it can hold a password or a token.
func TestProviderErrorsDoNotEchoTheValues(t *testing.T) {
	g := NewWithT(t)
	_, err := (&IdentityProviderValidator{}).ValidateCreate(context.Background(),
		identityProvider(providerConfig("https://user:hunter2@sso.example.com", "https://user:hunter2@sso.example.com"),
			"http://user:hunter2@proxy:3128"))
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).NotTo(ContainSubstring("hunter2"))
	g.Expect(err.Error()).NotTo(ContainSubstring("sso.example.com"))
	g.Expect(err.Error()).NotTo(ContainSubstring("proxy:3128"))
	g.Expect(err.Error()).To(And(ContainSubstring("spec.issuer"), ContainSubstring("spec.keycloak.baseURL"), ContainSubstring("spec.proxyURL")))
}

func oidcClient(public bool, redirect ...string) *oidcv1alpha1.OidcClient {
	uris := make([]oidcv1alpha1.RedirectURI, len(redirect))
	for i, r := range redirect {
		uris[i] = oidcv1alpha1.RedirectURI(r)
	}
	return &oidcv1alpha1.OidcClient{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       oidcv1alpha1.OidcClientSpec{Public: public, RedirectURIs: uris},
	}
}

func TestOidcClientValidator(t *testing.T) {
	v := &OidcClientValidator{}
	ctx := context.Background()
	for _, tc := range redirectCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			warnings, err := v.ValidateCreate(ctx, oidcClient(tc.public, tc.uri))
			g.Expect(warnings).To(BeEmpty())
			if tc.message == "" {
				g.Expect(err).NotTo(HaveOccurred())
			} else {
				expectField(g, err, "spec.redirectUris[0]", tc.message)
			}

			_, err = v.ValidateUpdate(ctx, oidcClient(tc.public, "https://old.example.com/cb"), oidcClient(tc.public, tc.uri))
			if tc.message == "" {
				g.Expect(err).NotTo(HaveOccurred())
			} else {
				expectField(g, err, "spec.redirectUris[0]", tc.message)
			}
		})
	}

	g := NewWithT(t)

	// Every URI is checked, and the error names its index.
	_, err := v.ValidateCreate(ctx, oidcClient(false, "https://ok.example.com/cb", "https://*.example.com/cb", "javascript:alert(1)"))
	expectField(g, err, "spec.redirectUris[1]", "wildcards")
	g.Expect(err.Error()).To(ContainSubstring("spec.redirectUris[2]"))
	g.Expect(err.Error()).NotTo(ContainSubstring("spec.redirectUris[0]"))

	// A client without a redirect URI is refused.
	_, err = v.ValidateCreate(ctx, oidcClient(false))
	expectField(g, err, "spec.redirectUris", "at least one redirect URI is required")

	// The post-logout URIs and the web origins follow the same rules.
	c := oidcClient(false, "https://ok.example.com/cb")
	c.Spec.PostLogoutRedirectURIs = []oidcv1alpha1.RedirectURI{"https://ok.example.com/bye", "http://localhost/bye", "https://x.example.com/#f"}
	c.Spec.WebOrigins = []oidcv1alpha1.WebOrigin{"https://ok.example.com", "https://ok.example.com/path", "*"}
	_, err = v.ValidateCreate(ctx, c)
	g.Expect(err).To(HaveOccurred())
	for _, want := range []string{
		"spec.postLogoutRedirectUris[1]", "spec.postLogoutRedirectUris[2]",
		"spec.webOrigins[1]", "spec.webOrigins[2]",
	} {
		g.Expect(err.Error()).To(ContainSubstring(want))
	}
	g.Expect(err.Error()).NotTo(ContainSubstring("spec.postLogoutRedirectUris[0]"))
	g.Expect(err.Error()).NotTo(ContainSubstring("spec.webOrigins[0]"))

	// A public client may use the loopback http URIs, in all three lists.
	c = oidcClient(true, "http://127.0.0.1:8080/cb")
	c.Spec.PostLogoutRedirectURIs = []oidcv1alpha1.RedirectURI{"http://localhost/bye"}
	c.Spec.WebOrigins = []oidcv1alpha1.WebOrigin{"http://localhost:3000"}
	_, err = v.ValidateCreate(ctx, c)
	g.Expect(err).NotTo(HaveOccurred())

	// An object being deleted is admitted while its spec is unchanged.
	deleting := oidcClient(false, "javascript:alert(1)")
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	_, err = v.ValidateUpdate(ctx, oidcClient(false, "javascript:alert(1)"), deleting)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = v.ValidateUpdate(ctx, oidcClient(false, "https://ok.example.com/cb"), deleting)
	g.Expect(err).To(HaveOccurred())
	_, err = v.ValidateDelete(ctx, oidcClient(false, "javascript:alert(1)"))
	g.Expect(err).NotTo(HaveOccurred())
}

// An admission error never echoes a redirect URI: it can hold a token.
func TestClientErrorsDoNotEchoTheValues(t *testing.T) {
	g := NewWithT(t)
	_, err := (&OidcClientValidator{}).ValidateCreate(context.Background(),
		oidcClient(false, "https://user:hunter2@app.example.com/cb?token=s3cret"))
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).NotTo(ContainSubstring("hunter2"))
	g.Expect(err.Error()).NotTo(ContainSubstring("s3cret"))
	g.Expect(err.Error()).NotTo(ContainSubstring("app.example.com"))
}
