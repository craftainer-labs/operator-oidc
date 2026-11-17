package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
)

// IdentityProviderSpec defines the desired state of IdentityProvider.
//
// +kubebuilder:validation:XValidation:rule="self.type == 'Keycloak' ? (has(self.keycloak) && !has(self.dynamicRegistration) && !has(self.cognito) && !has(self.entra)) : self.type == 'DynamicRegistration' ? (has(self.dynamicRegistration) && !has(self.keycloak) && !has(self.cognito) && !has(self.entra)) : self.type == 'Cognito' ? (has(self.cognito) && !has(self.keycloak) && !has(self.dynamicRegistration) && !has(self.entra)) : (has(self.entra) && !has(self.keycloak) && !has(self.dynamicRegistration) && !has(self.cognito))",message="exactly the block matching type must be set: keycloak for Keycloak, dynamicRegistration for DynamicRegistration, cognito for Cognito, entra for Entra"
// +kubebuilder:validation:XValidation:rule="self.type in ['Cognito', 'Entra'] ? !has(self.issuer) : has(self.issuer)",message="issuer is required for Keycloak and DynamicRegistration and forbidden for Cognito and Entra (it is derived from the user pool or the tenant)"
// +kubebuilder:validation:XValidation:rule="!has(self.credentials) || self.type in ['Cognito', 'Entra']",message="credentials is only for a cloud provider (type Cognito or Entra)"
// +kubebuilder:validation:XValidation:rule="!(self.type in ['Cognito', 'Entra']) || has(self.credentials)",message="a namespaced cloud provider (Cognito or Entra) must set credentials with source Secret: it cannot use the operator's workload identity"
// +kubebuilder:validation:XValidation:rule="self.type in ['Cognito', 'Entra'] ? !has(self.adminCredentialsSecretRef) : has(self.adminCredentialsSecretRef)",message="adminCredentialsSecretRef is required, except for type Cognito or Entra, where it is forbidden (the cloud credential is credentials)"
// +kubebuilder:validation:XValidation:rule="!has(self.adminCredentialsSecretRef) || !has(self.adminCredentialsSecretRef.namespace)",message="adminCredentialsSecretRef.namespace must not be set: the Secret is in the IdentityProvider's namespace"
// +kubebuilder:validation:XValidation:rule="!has(self.cognito) || !has(self.cognito.endpointOverride)",message="cognito.endpointOverride is only for a cluster-scoped provider"
// +kubebuilder:validation:XValidation:rule="!has(self.entra) || !has(self.entra.endpointOverride)",message="entra.endpointOverride is only for a cluster-scoped provider"
type IdentityProviderSpec struct {
	common.CloudServerCommon `json:",inline"`
	ProviderConfig           `json:",inline"`

	// credentials are the cloud credentials of a provider of type Cognito or Entra:
	// always a Secret in the provider's own namespace (a tenant-created
	// provider cannot use the operator's workload identity), with the keys
	// accessKeyId, secretAccessKey and optionally sessionToken (Cognito), or
	// clientId and clientSecret (Entra).
	//
	// +optional
	Credentials *cloud.NamespacedCredentials `json:"credentials,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=craftainer
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// IdentityProvider is an identity provider (Keycloak, or a provider with dynamic client
// registration) that only claims in its own namespace may use.
type IdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of IdentityProvider
	// +required
	Spec IdentityProviderSpec `json:"spec"`

	// status defines the observed state of IdentityProvider
	// +optional
	Status IdentityProviderStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// IdentityProviderList contains a list of IdentityProvider.
type IdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []IdentityProvider `json:"items"`
}

// GetCloudCommon returns the settings every cloud-capable server kind shares
// (server.CloudServer).
func (s *IdentityProvider) GetCloudCommon() *common.CloudServerCommon {
	return &s.Spec.CloudServerCommon
}

// GetCredentialsSecret returns the name of spec.credentials.secretRef and an
// empty namespace: the Secret is in the provider's own namespace.
func (s *IdentityProvider) GetCredentialsSecret() (name, namespace string) {
	return credentialsSecret(s.Spec.Credentials.AsCredentials())
}

// GetServerStatus returns the status the probe writes (probe.Server).
func (s *IdentityProvider) GetServerStatus() *common.ServerStatus { return &s.Status.ServerStatus }

// GetEndpoint returns the server's URL, the Keycloak base URL or the registration
// endpoint; empty for a cloud provider, whose endpoint is the cloud's.
func (s *IdentityProvider) GetEndpoint() string { return s.Spec.Endpoint() }

// GetAllowedNamespaces returns nil: a namespaced server serves only its own
// namespace.
func (s *IdentityProvider) GetAllowedNamespaces() *common.AllowedNamespaces { return nil }

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &IdentityProvider{}, &IdentityProviderList{})
		return nil
	})
}
