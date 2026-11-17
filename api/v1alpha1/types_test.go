package v1alpha1

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/probe"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"
)

// The claim kind and the server kinds must satisfy the interfaces the
// lib-operator-go reconciler is written against.
var (
	_ lifecycle.Claim    = (*OidcClient)(nil)
	_ server.CloudServer = (*IdentityProvider)(nil)
	_ server.CloudServer = (*ClusterIdentityProvider)(nil)
	_ probe.CloudServer  = (*IdentityProvider)(nil)
	_ probe.CloudServer  = (*ClusterIdentityProvider)(nil)
)

func TestAddToSchemeRegistersEveryKind(t *testing.T) {
	g := NewWithT(t)
	s := runtime.NewScheme()
	g.Expect(AddToScheme(s)).To(Succeed())
	for _, kind := range []string{
		"ClusterIdentityProvider", "ClusterIdentityProviderList", "IdentityProvider", "IdentityProviderList",
		"OidcClient", "OidcClientList",
	} {
		g.Expect(s.Recognizes(GroupVersion.WithKind(kind))).To(BeTrue(), kind)
	}
	g.Expect(GroupVersion.Group).To(Equal("oidc.craftainer.dev"))
}

func TestEndpointIsTheKeycloakBaseURLOrTheRegistrationEndpoint(t *testing.T) {
	g := NewWithT(t)
	for _, tc := range []struct {
		name   string
		config ProviderConfig
		want   string
	}{
		{"Keycloak", ProviderConfig{Type: ProviderKeycloak, Keycloak: &KeycloakConfig{BaseURL: "https://sso.example.com"}}, "https://sso.example.com"},
		{"DynamicRegistration", ProviderConfig{Type: ProviderDynamicRegistration, DynamicRegistration: &DynamicRegistrationConfig{RegistrationEndpoint: "https://idp.example.com/register"}}, "https://idp.example.com/register"},
		{"Keycloak without its block", ProviderConfig{Type: ProviderKeycloak}, ""},
		{"DynamicRegistration without its block", ProviderConfig{Type: ProviderDynamicRegistration}, ""},
		{"Cognito has no URL of its own", ProviderConfig{Type: ProviderCognito, Cognito: &CognitoConfig{UserPoolID: "eu-west-1_Ab"}}, ""},
		{"unknown type", ProviderConfig{Type: "Other", Keycloak: &KeycloakConfig{BaseURL: "https://x"}}, ""},
	} {
		g.Expect(tc.config.Endpoint()).To(Equal(tc.want), tc.name)
	}
}

func TestIdentityProviderAccessors(t *testing.T) {
	g := NewWithT(t)
	b := &IdentityProvider{Spec: IdentityProviderSpec{
		CloudServerCommon: common.CloudServerCommon{ProxyURL: "http://proxy:3128"},
		ProviderConfig:    ProviderConfig{Type: ProviderKeycloak, Keycloak: &KeycloakConfig{BaseURL: "https://sso.example.com"}},
	}}
	g.Expect(b.GetCloudCommon().ProxyURL).To(Equal("http://proxy:3128"))
	g.Expect(b.GetEndpoint()).To(Equal("https://sso.example.com"))
	name, ns := b.GetCredentialsSecret()
	g.Expect(name).To(BeEmpty())
	g.Expect(ns).To(BeEmpty())
	b.Spec.Credentials = &cloud.NamespacedCredentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "aws"}}
	name, ns = b.GetCredentialsSecret()
	g.Expect(name).To(Equal("aws"))
	g.Expect(ns).To(BeEmpty())
	g.Expect(b.GetAllowedNamespaces()).To(BeNil())
	b.GetServerStatus().ServerVersion = "26.0"
	g.Expect(b.Status.ServerVersion).To(Equal("26.0"))
}

func TestClusterIdentityProviderAccessors(t *testing.T) {
	g := NewWithT(t)
	b := &ClusterIdentityProvider{Spec: ClusterIdentityProviderSpec{
		CloudServerCommon: common.CloudServerCommon{ProxyURL: "http://proxy:3128"},
		ProviderConfig:    ProviderConfig{Type: ProviderDynamicRegistration, DynamicRegistration: &DynamicRegistrationConfig{RegistrationEndpoint: "https://idp.example.com/register"}},
		AllowedNamespaces: common.AllowedNamespaces{From: common.NamespacesAll},
	}}
	g.Expect(b.GetCloudCommon().ProxyURL).To(Equal("http://proxy:3128"))
	g.Expect(b.GetEndpoint()).To(Equal("https://idp.example.com/register"))
	name, ns := b.GetCredentialsSecret()
	g.Expect(name).To(BeEmpty())
	g.Expect(ns).To(BeEmpty())
	// Workload identity names no Secret; a Secret source names it with its namespace.
	b.Spec.Credentials = &cloud.Credentials{Source: cloud.SourceWorkloadIdentity}
	name, _ = b.GetCredentialsSecret()
	g.Expect(name).To(BeEmpty())
	b.Spec.Credentials = &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "aws", Namespace: "ops"}}
	name, ns = b.GetCredentialsSecret()
	g.Expect(name).To(Equal("aws"))
	g.Expect(ns).To(Equal("ops"))
	g.Expect(b.GetAllowedNamespaces().From).To(Equal(common.NamespacesAll))
	b.GetServerStatus().ServerVersion = "1.0"
	g.Expect(b.Status.ServerVersion).To(Equal("1.0"))
}

func TestOidcClientAccessors(t *testing.T) {
	g := NewWithT(t)
	rotation := &common.RotationPolicy{}
	u := &OidcClient{
		ObjectMeta: metav1.ObjectMeta{Name: "web"},
		Spec: OidcClientSpec{
			ClaimCommon: common.ClaimCommon{
				ServerRef:          common.ServerRef{Kind: "ClusterIdentityProvider", Name: "valkey"},
				ManagementPolicies: []common.ManagementPolicy{common.ManagementAll},
			},
			Credentials: common.Credentials{RotationPolicy: rotation},
		},
	}
	g.Expect(u.GetServerRef()).To(Equal(common.ServerRef{Kind: "ClusterIdentityProvider", Name: "valkey"}))
	g.Expect(u.GetDeletionPolicy()).To(BeEmpty())
	g.Expect(u.GetManagementPolicies()).To(Equal([]common.ManagementPolicy{common.ManagementAll}))

	*u.GetConditions() = append(*u.GetConditions(), metav1.Condition{Type: "Synced"})
	g.Expect(u.Status.Conditions).To(HaveLen(1))

	// The binding Secret is named after the claim unless the spec names it.
	g.Expect(u.GetBindingSecretName()).To(Equal("web"))
	u.Spec.Binding.SecretName = "web-oidc"
	g.Expect(u.GetBindingSecretName()).To(Equal("web-oidc"))
	u.SetBindingName("web-oidc")
	g.Expect(u.Status.Binding.Name).To(Equal("web-oidc"))

	u.SetExternalName("web")
	g.Expect(u.GetExternalName()).To(Equal("web"))
	u.SetExternalID("id-1")
	g.Expect(u.GetExternalID()).To(Equal("id-1"))
	u.SetObservedGeneration(4)
	g.Expect(u.Status.ObservedGeneration).To(Equal(int64(4)))
	now := metav1.NewTime(time.Unix(1700000000, 0))
	u.SetLastReconcileTime(now)
	g.Expect(u.Status.LastReconcileTime.Equal(&now)).To(BeTrue())

	u.SetEffectiveDeletionPolicy(common.DeletionRetain, common.SourceFallback)
	g.Expect(u.GetEffectiveDeletionPolicy()).To(BeEmpty())

	u.SetLateInitialized(map[string]string{"k": "v"})
	g.Expect(u.Status.LateInitialized).To(HaveKeyWithValue("k", "v"))

	g.Expect(u.GetRotationPolicy()).To(BeIdenticalTo(rotation))
	g.Expect(u.GetRotationStatus()).To(Equal(common.RotationStatus{}))
	u.SetRotationStatus(common.RotationStatus{Active: "g1", Sequence: 2})
	g.Expect(u.GetRotationStatus()).To(Equal(common.RotationStatus{Active: "g1", Sequence: 2}))
}
