package v1alpha1

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
)

// These specs send objects through the API server with the generated CRDs
// installed, so they check the schema defaults and the CEL rules next to the
// webhooks: the CRDs are the API's contract and the webhooks only add to it.
var _ = Describe("The oidc.craftainer.dev CRDs", func() {
	const ns = "default"

	// create creates obj and deletes it when the spec ends.
	create := func(obj client.Object) error {
		err := k8sClient.Create(ctx, obj)
		if err == nil {
			DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed()) })
		}
		return err
	}
	// rejectedAt expects an error that names the field, or the rule of the
	// spec that ties the URI to the client type (its path is spec).
	rejectedAt := func(err error, field string) {
		GinkgoHelper()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Or(ContainSubstring(field), ContainSubstring("only on a public client")))
	}
	rejected := func(err error, substring string) {
		GinkgoHelper()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(substring))
	}

	keycloak := func() oidcv1alpha1.ProviderConfig {
		return oidcv1alpha1.ProviderConfig{
			Type:     oidcv1alpha1.ProviderKeycloak,
			Issuer:   "https://sso.example.com/realms/craftainer",
			Keycloak: &oidcv1alpha1.KeycloakConfig{BaseURL: "https://sso.example.com", Realm: "craftainer"},
		}
	}
	dynamic := func() oidcv1alpha1.ProviderConfig {
		return oidcv1alpha1.ProviderConfig{
			Type:   oidcv1alpha1.ProviderDynamicRegistration,
			Issuer: "https://idp.example.com",
			DynamicRegistration: &oidcv1alpha1.DynamicRegistrationConfig{
				RegistrationEndpoint:        "https://idp.example.com/register",
				InitialAccessTokenSecretRef: &oidcv1alpha1.SecretKeyRef{Name: "iat", Key: "token"},
			},
		}
	}
	clusterProvider := func(name string) *oidcv1alpha1.ClusterIdentityProvider {
		return &oidcv1alpha1.ClusterIdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: oidcv1alpha1.ClusterIdentityProviderSpec{
				ServerCommon:      common.ServerCommon{AdminCredentialsSecretRef: common.AdminSecretRef{Name: "admin", Namespace: "craftainer-system"}},
				ProviderConfig:    keycloak(),
				AllowedNamespaces: common.AllowedNamespaces{From: common.NamespacesAll},
			},
		}
	}
	provider := func(name string) *oidcv1alpha1.IdentityProvider {
		return &oidcv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: oidcv1alpha1.IdentityProviderSpec{
				ServerCommon:   common.ServerCommon{AdminCredentialsSecretRef: common.AdminSecretRef{Name: "admin"}},
				ProviderConfig: keycloak(),
			},
		}
	}
	oidcClientObj := func(name string, uris ...string) *oidcv1alpha1.OidcClient {
		c := &oidcv1alpha1.OidcClient{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: oidcv1alpha1.OidcClientSpec{
				ClaimCommon: common.ClaimCommon{ServerRef: common.ServerRef{Kind: "IdentityProvider", Name: "keycloak"}},
			},
		}
		for _, u := range uris {
			c.Spec.RedirectURIs = append(c.Spec.RedirectURIs, oidcv1alpha1.RedirectURI(u))
		}
		return c
	}
	web := func(name string) *oidcv1alpha1.OidcClient { return oidcClientObj(name, "https://app.example.com/cb") }

	Describe("ClusterIdentityProvider", func() {
		It("applies the schema defaults", func() {
			Expect(create(clusterProvider("defaults"))).To(Succeed())
			got := &oidcv1alpha1.ClusterIdentityProvider{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "defaults"}, got)).To(Succeed())
			Expect(got.Spec.AllowedScopes).To(Equal([]oidcv1alpha1.Scope{"openid", "profile", "email"}))
			Expect(got.GetEndpoint()).To(Equal("https://sso.example.com"))
		})

		It("admits a dynamic registration provider", func() {
			p := clusterProvider("dynamic")
			p.Spec.ProviderConfig = dynamic()
			Expect(create(p)).To(Succeed())
		})

		It("requires the admin Secret's namespace", func() {
			p := clusterProvider("no-ns")
			p.Spec.AdminCredentialsSecretRef.Namespace = ""
			rejected(create(p), "adminCredentialsSecretRef.namespace is required")
		})

		It("fails closed without a valid allowedNamespaces", func() {
			p := clusterProvider("no-from")
			p.Spec.AllowedNamespaces = common.AllowedNamespaces{}
			rejected(create(p), "allowedNamespaces")

			p = clusterProvider("selector-missing")
			p.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesSelector}
			rejected(create(p), "selector is required when from is Selector")

			p = clusterProvider("selector-empty")
			p.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesSelector, Selector: &common.LabelSelector{}}
			rejected(create(p), "selector must have matchLabels or matchExpressions")
		})

		It("needs exactly the block that matches the type", func() {
			p := clusterProvider("no-block")
			p.Spec.Keycloak = nil
			rejected(create(p), "exactly the block matching type must be set")

			p = clusterProvider("both-blocks")
			p.Spec.DynamicRegistration = dynamic().DynamicRegistration
			rejected(create(p), "exactly the block matching type must be set")

			p = clusterProvider("wrong-block")
			p.Spec.ProviderConfig = dynamic()
			p.Spec.Type = oidcv1alpha1.ProviderKeycloak
			rejected(create(p), "exactly the block matching type must be set")

			p = clusterProvider("unknown-type")
			p.Spec.Type = "Saml"
			rejected(create(p), "type")
		})

		It("keeps the type immutable", func() {
			p := clusterProvider("pinned")
			Expect(create(p)).To(Succeed())
			p.Spec.ProviderConfig = dynamic()
			rejected(k8sClient.Update(ctx, p), "type is immutable")
		})

		It("rejects a URL that is not an https URL with a host, without userinfo, query or fragment", func() {
			for _, issuer := range []string{
				"http://sso.example.com/realms/x", "sso.example.com", "https://", "https:///realms/x",
				"https://user@sso.example.com", "https://sso.example.com/x?a=b", "https://sso.example.com/x#f",
				"https://sso.example.com/a b", `https://sso.example.com\x`, "javascript:alert(1)",
			} {
				p := clusterProvider("bad-issuer")
				p.Spec.Issuer = oidcv1alpha1.HTTPSURL(issuer)
				rejected(create(p), "spec.issuer")
			}
			p := clusterProvider("bad-base")
			p.Spec.Keycloak.BaseURL = "http://sso.example.com"
			rejected(create(p), "spec.keycloak.baseURL")

			p = clusterProvider("bad-realm")
			p.Spec.Keycloak.Realm = "../admin"
			rejected(create(p), "spec.keycloak.realm")

			p = clusterProvider("bad-endpoint")
			p.Spec.ProviderConfig = dynamic()
			p.Spec.DynamicRegistration.RegistrationEndpoint = "http://idp.example.com/register"
			rejected(create(p), "spec.dynamicRegistration.registrationEndpoint")
		})

		It("rejects a malformed allowed scope", func() {
			for _, scope := range []string{"a b", `a"b`, `a\b`, ""} {
				p := clusterProvider("bad-scope")
				p.Spec.AllowedScopes = []oidcv1alpha1.Scope{oidcv1alpha1.Scope(scope)}
				rejected(create(p), "allowedScopes")
			}
		})

		It("rejects a proxy URL with credentials in the webhook, without echoing it", func() {
			p := clusterProvider("proxy-userinfo")
			p.Spec.ProxyURL = "http://user:hunter2@proxy:3128"
			err := create(p)
			rejected(err, "must not carry credentials")
			Expect(err.Error()).NotTo(ContainSubstring("hunter2"))
		})

		It("rejects an issuer the schema cannot judge in the webhook", func() {
			p := clusterProvider("bad-host")
			p.Spec.Issuer = "https://sso_1.example.com/realms/x"
			rejected(create(p), "must have a host name or an IP address as its host")
		})
	})

	Describe("IdentityProvider", func() {
		It("is admitted with the Secret in its own namespace", func() {
			Expect(create(provider("plain"))).To(Succeed())
		})

		It("forbids a namespace on the admin Secret", func() {
			p := provider("with-ns")
			p.Spec.AdminCredentialsSecretRef.Namespace = "elsewhere"
			rejected(create(p), "adminCredentialsSecretRef.namespace must not be set")
		})

		It("keeps the initial access token reference to a name and a key", func() {
			p := provider("iat")
			p.Spec.ProviderConfig = dynamic()
			Expect(create(p)).To(Succeed())

			p = provider("iat-no-key")
			p.Spec.ProviderConfig = dynamic()
			p.Spec.DynamicRegistration.InitialAccessTokenSecretRef.Key = ""
			rejected(create(p), "initialAccessTokenSecretRef")
		})

		It("accepts the TLS settings of the common server block", func() {
			p := provider("tls")
			p.Spec.TLS = &common.TLS{ServerName: "sso.example.com", CABundle: &common.CABundle{SecretRef: &common.KeyReference{Name: "ca"}}}
			Expect(create(p)).To(Succeed())
			got := &oidcv1alpha1.IdentityProvider{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(p), got)).To(Succeed())
			Expect(got.Spec.TLS.MinVersion).To(Equal(common.TLS12))
		})
	})

	Describe("OidcClient", func() {
		It("applies the schema defaults", func() {
			Expect(create(web("defaults"))).To(Succeed())
			got := &oidcv1alpha1.OidcClient{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "defaults"}, got)).To(Succeed())
			Expect(got.Spec.ManagementPolicies).To(Equal([]common.ManagementPolicy{common.ManagementAll}))
			Expect(got.Spec.Public).To(BeFalse())
			Expect(got.Spec.GrantTypes).To(Equal([]oidcv1alpha1.GrantType{oidcv1alpha1.GrantAuthorizationCode}))
			Expect(got.Spec.PKCE).To(Equal(oidcv1alpha1.PKCES256))
			Expect(got.Spec.Scopes).To(Equal([]oidcv1alpha1.Scope{"openid"}))
			Expect(got.Spec.TokenEndpointAuthMethod).To(BeEmpty())
			Expect(got.Spec.RotationPolicy).To(BeNil())
		})

		// The same URIs the unit tests give the webhook: whichever of the CEL
		// rules and the webhook rejects one, a rejected URI never gets in and
		// an accepted one gets through both.
		Describe("redirect URIs", func() {
			for i, tc := range redirectCases {
				name := fmt.Sprintf("uri-%d", i)
				It("handles "+tc.name, func() {
					c := oidcClientObj(name, tc.uri)
					c.Spec.Public = tc.public
					if tc.public {
						c.Spec.TokenEndpointAuthMethod = oidcv1alpha1.AuthMethodNone
					}
					err := create(c)
					if tc.message == "" {
						Expect(err).NotTo(HaveOccurred())
						return
					}
					rejectedAt(err, "spec.redirectUris[0]")
				})
				It("handles "+tc.name+" as a post-logout URI", func() {
					c := web(name + "-logout")
					c.Spec.Public = tc.public
					if tc.public {
						c.Spec.TokenEndpointAuthMethod = oidcv1alpha1.AuthMethodNone
					}
					c.Spec.PostLogoutRedirectURIs = []oidcv1alpha1.RedirectURI{oidcv1alpha1.RedirectURI(tc.uri)}
					err := create(c)
					if tc.message == "" {
						Expect(err).NotTo(HaveOccurred())
						return
					}
					rejectedAt(err, "spec.postLogoutRedirectUris[0]")
				})
			}

			It("requires at least one and at most 20", func() {
				rejected(create(oidcClientObj("none")), "redirectUris")
				var many []string
				for i := range 21 {
					many = append(many, fmt.Sprintf("https://app%d.example.com/cb", i))
				}
				rejected(create(oidcClientObj("many", many...)), "redirectUris")
			})

			It("rejects a duplicate", func() {
				rejected(create(oidcClientObj("dup", "https://a.example.com/cb", "https://a.example.com/cb")), "redirectUris")
			})
		})

		It("handles the web origins", func() {
			c := web("origins")
			c.Spec.WebOrigins = []oidcv1alpha1.WebOrigin{"https://app.example.com", "https://app.example.com:8443"}
			Expect(create(c)).To(Succeed())

			for _, origin := range []string{"*", "+", "https://app.example.com/", "https://app.example.com/x", "http://app.example.com", "https://*.example.com", "https://app.example.com?x"} {
				c = web("bad-origin")
				c.Spec.WebOrigins = []oidcv1alpha1.WebOrigin{oidcv1alpha1.WebOrigin(origin)}
				rejected(create(c), "webOrigins")
			}
		})

		It("allows a loopback origin on a public client only", func() {
			c := web("loopback-origin")
			c.Spec.WebOrigins = []oidcv1alpha1.WebOrigin{"http://localhost:3000"}
			rejected(create(c), "only on a public client")

			c.Spec.Public = true
			c.Spec.TokenEndpointAuthMethod = oidcv1alpha1.AuthMethodNone
			Expect(create(c)).To(Succeed())
		})

		It("accepts a native app: a public client with a loopback redirect", func() {
			c := oidcClientObj("native", "http://127.0.0.1:8080/cb")
			c.Spec.Public = true
			c.Spec.GrantTypes = []oidcv1alpha1.GrantType{oidcv1alpha1.GrantAuthorizationCode, oidcv1alpha1.GrantRefreshToken}
			c.Spec.TokenEndpointAuthMethod = oidcv1alpha1.AuthMethodNone
			Expect(create(c)).To(Succeed())
		})

		It("rejects a confidential client with a loopback redirect", func() {
			rejected(create(oidcClientObj("confidential-loopback", "http://localhost:8080/cb")), "only on a public client")
		})

		It("limits the grant types to the three it knows", func() {
			c := web("bad-grant")
			c.Spec.GrantTypes = []oidcv1alpha1.GrantType{"password"}
			rejected(create(c), "grantTypes")

			c = web("implicit")
			c.Spec.GrantTypes = []oidcv1alpha1.GrantType{"implicit"}
			rejected(create(c), "grantTypes")

			c = web("all-grants")
			c.Spec.GrantTypes = []oidcv1alpha1.GrantType{oidcv1alpha1.GrantAuthorizationCode, oidcv1alpha1.GrantRefreshToken, oidcv1alpha1.GrantClientCredentials}
			Expect(create(c)).To(Succeed())

			c = web("no-grants")
			c.Spec.GrantTypes = []oidcv1alpha1.GrantType{}
			rejected(create(c), "grantTypes")
		})

		It("needs a confidential client for the client_credentials grant", func() {
			c := web("public-service")
			c.Spec.Public = true
			c.Spec.TokenEndpointAuthMethod = oidcv1alpha1.AuthMethodNone
			c.Spec.GrantTypes = []oidcv1alpha1.GrantType{oidcv1alpha1.GrantClientCredentials}
			rejected(create(c), "client_credentials grant needs a confidential client")
		})

		It("ties tokenEndpointAuthMethod none to public", func() {
			c := web("secret-none")
			c.Spec.TokenEndpointAuthMethod = oidcv1alpha1.AuthMethodNone
			rejected(create(c), "tokenEndpointAuthMethod none is for public clients and only for them")

			c = web("public-basic")
			c.Spec.Public = true
			c.Spec.TokenEndpointAuthMethod = oidcv1alpha1.AuthMethodClientSecretBasic
			rejected(create(c), "tokenEndpointAuthMethod none is for public clients and only for them")

			c = web("post")
			c.Spec.TokenEndpointAuthMethod = oidcv1alpha1.AuthMethodClientSecretPost
			Expect(create(c)).To(Succeed())

			c = web("unknown-method")
			c.Spec.TokenEndpointAuthMethod = "private_key_jwt"
			rejected(create(c), "tokenEndpointAuthMethod")
		})

		It("requires PKCE of a public client", func() {
			c := web("public-no-pkce")
			c.Spec.Public = true
			c.Spec.PKCE = oidcv1alpha1.PKCEDisabled
			rejected(create(c), "a public client must use PKCE")

			c = web("confidential-no-pkce")
			c.Spec.PKCE = oidcv1alpha1.PKCEDisabled
			Expect(create(c)).To(Succeed())

			c = web("unknown-pkce")
			c.Spec.PKCE = "plain"
			rejected(create(c), "pkce")
		})

		It("allows a rotationPolicy on a confidential client only, and with the Update policy", func() {
			rotation := &common.RotationPolicy{Interval: &metav1.Duration{Duration: 2160 * time.Hour}}

			c := web("rotating")
			c.Spec.RotationPolicy = rotation
			Expect(create(c)).To(Succeed())

			c = web("public-rotating")
			c.Spec.Public = true
			c.Spec.RotationPolicy = rotation
			rejected(create(c), "rotationPolicy is allowed only on a confidential client")

			c = web("no-update")
			c.Spec.ManagementPolicies = []common.ManagementPolicy{common.ManagementObserve, common.ManagementCreate}
			c.Spec.RotationPolicy = rotation
			rejected(create(c), "rotationPolicy needs the Update management policy")
		})

		It("checks the scopes", func() {
			c := web("scopes")
			c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "profile", "offline_access", "https://example.com/scope"}
			Expect(create(c)).To(Succeed())

			for _, scope := range []string{"a b", `a"b`, `a\b`, ""} {
				c = web("bad-scope")
				c.Spec.Scopes = []oidcv1alpha1.Scope{oidcv1alpha1.Scope(scope)}
				rejected(create(c), "scopes")
			}
		})

		It("has no deletionPolicy, and prunes it", func() {
			u := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "oidc.craftainer.dev/v1alpha1",
				"kind":       "OidcClient",
				"metadata":   map[string]any{"name": "pruned", "namespace": ns},
				"spec": map[string]any{
					"serverRef":      map[string]any{"kind": "IdentityProvider", "name": "keycloak"},
					"redirectUris":   []any{"https://app.example.com/cb"},
					"deletionPolicy": "Retain",
				},
			}}
			Expect(create(u)).To(Succeed())
			stored := &unstructured.Unstructured{}
			stored.SetGroupVersionKind(oidcv1alpha1.GroupVersion.WithKind("OidcClient"))
			Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: ns, Name: "pruned"}, stored)).To(Succeed())
			spec, _, _ := unstructured.NestedMap(stored.Object, "spec")
			Expect(spec).NotTo(HaveKey("deletionPolicy"))
		})

		It("rejects a server kind of another group", func() {
			c := web("other-kind")
			c.Spec.ServerRef.Kind = "DatabaseServer"
			rejected(create(c), "serverRef.kind must be ClusterIdentityProvider or IdentityProvider")
		})

		It("keeps serverRef immutable", func() {
			c := web("pinned")
			Expect(create(c)).To(Succeed())
			c.Spec.ServerRef.Name = "other"
			rejected(k8sClient.Update(ctx, c), "serverRef is immutable")
		})
	})
})
