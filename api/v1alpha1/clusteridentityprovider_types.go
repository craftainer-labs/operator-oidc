package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
)

// +kubebuilder:validation:XValidation:rule="self.type == 'Keycloak' ? (has(self.keycloak) && !has(self.dynamicRegistration)) : (has(self.dynamicRegistration) && !has(self.keycloak))",message="exactly the block matching type must be set: keycloak for Keycloak, dynamicRegistration for DynamicRegistration"
// +kubebuilder:validation:XValidation:rule="has(self.adminCredentialsSecretRef.namespace) && self.adminCredentialsSecretRef.namespace != ''",message="adminCredentialsSecretRef.namespace is required on a cluster-scoped server"

// ClusterIdentityProviderSpec defines the desired state of ClusterIdentityProvider.
type ClusterIdentityProviderSpec struct {
	common.ServerCommon `json:",inline"`
	ProviderConfig      `json:",inline"`

	// allowedNamespaces says which namespaces may claim from this server. It is
	// required, so a server without it is rejected: it fails closed.
	AllowedNamespaces common.AllowedNamespaces `json:"allowedNamespaces"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=craftainer
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterIdentityProvider is a cluster-scoped identity provider (Keycloak, or a provider with
// dynamic client registration) that the namespaces in allowedNamespaces may claim
// clients from.
type ClusterIdentityProvider struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ClusterIdentityProvider
	// +required
	Spec ClusterIdentityProviderSpec `json:"spec"`

	// status defines the observed state of ClusterIdentityProvider
	// +optional
	Status IdentityProviderStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ClusterIdentityProviderList contains a list of ClusterIdentityProvider.
type ClusterIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ClusterIdentityProvider `json:"items"`
}

// GetCommon returns the settings every server kind shares.
func (s *ClusterIdentityProvider) GetCommon() *common.ServerCommon { return &s.Spec.ServerCommon }

// GetServerStatus returns the status the probe writes (probe.Server).
func (s *ClusterIdentityProvider) GetServerStatus() *common.ServerStatus {
	return &s.Status.ServerStatus
}

// GetEndpoint returns the server's URL, the Keycloak base URL or the registration endpoint.
func (s *ClusterIdentityProvider) GetEndpoint() string { return s.Spec.Endpoint() }

// GetAllowedNamespaces returns spec.allowedNamespaces.
func (s *ClusterIdentityProvider) GetAllowedNamespaces() *common.AllowedNamespaces {
	return &s.Spec.AllowedNamespaces
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ClusterIdentityProvider{}, &ClusterIdentityProviderList{})
		return nil
	})
}
