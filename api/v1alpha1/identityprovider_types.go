package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
)

// IdentityProviderSpec defines the desired state of IdentityProvider.
//
// +kubebuilder:validation:XValidation:rule="self.type == 'Keycloak' ? (has(self.keycloak) && !has(self.dynamicRegistration)) : (has(self.dynamicRegistration) && !has(self.keycloak))",message="exactly the block matching type must be set: keycloak for Keycloak, dynamicRegistration for DynamicRegistration"
// +kubebuilder:validation:XValidation:rule="!has(self.adminCredentialsSecretRef.namespace)",message="adminCredentialsSecretRef.namespace must not be set: the Secret is in the IdentityProvider's namespace"
type IdentityProviderSpec struct {
	common.ServerCommon `json:",inline"`
	ProviderConfig      `json:",inline"`
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

// GetCommon returns the settings every server kind shares.
func (s *IdentityProvider) GetCommon() *common.ServerCommon { return &s.Spec.ServerCommon }

// GetServerStatus returns the status the probe writes (probe.Server).
func (s *IdentityProvider) GetServerStatus() *common.ServerStatus { return &s.Status.ServerStatus }

// GetEndpoint returns the server's URL, the Keycloak base URL or the registration endpoint.
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
