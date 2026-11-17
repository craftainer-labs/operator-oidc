package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
)

// +kubebuilder:validation:XValidation:rule="self.type == 'Keycloak' ? (has(self.keycloak) && !has(self.dynamicRegistration) && !has(self.cognito) && !has(self.entra)) : self.type == 'DynamicRegistration' ? (has(self.dynamicRegistration) && !has(self.keycloak) && !has(self.cognito) && !has(self.entra)) : self.type == 'Cognito' ? (has(self.cognito) && !has(self.keycloak) && !has(self.dynamicRegistration) && !has(self.entra)) : (has(self.entra) && !has(self.keycloak) && !has(self.dynamicRegistration) && !has(self.cognito))",message="exactly the block matching type must be set: keycloak for Keycloak, dynamicRegistration for DynamicRegistration, cognito for Cognito, entra for Entra"
// +kubebuilder:validation:XValidation:rule="self.type in ['Cognito', 'Entra'] ? !has(self.issuer) : has(self.issuer)",message="issuer is required for Keycloak and DynamicRegistration and forbidden for Cognito and Entra (it is derived from the user pool or the tenant)"
// +kubebuilder:validation:XValidation:rule="!has(self.credentials) || self.type in ['Cognito', 'Entra']",message="credentials is only for a cloud provider (type Cognito or Entra)"
// +kubebuilder:validation:XValidation:rule="self.type in ['Cognito', 'Entra'] ? !has(self.adminCredentialsSecretRef) : has(self.adminCredentialsSecretRef)",message="adminCredentialsSecretRef is required, except for type Cognito or Entra, where it is forbidden (the cloud credential is credentials)"
// +kubebuilder:validation:XValidation:rule="!has(self.adminCredentialsSecretRef) || (has(self.adminCredentialsSecretRef.namespace) && size(self.adminCredentialsSecretRef.namespace) > 0)",message="adminCredentialsSecretRef.namespace is required on a cluster-scoped server"

// ClusterIdentityProviderSpec defines the desired state of ClusterIdentityProvider.
type ClusterIdentityProviderSpec struct {
	common.CloudServerCommon `json:",inline"`
	ProviderConfig           `json:",inline"`

	// credentials say where the operator gets its cloud credential for a
	// provider of type Cognito or Entra: its own workload identity (IRSA or
	// EKS Pod Identity, or Azure Workload Identity; the default) or a Secret in
	// the operator namespace holding the keys accessKeyId, secretAccessKey and
	// optionally sessionToken (Cognito), or clientId and clientSecret (Entra).
	//
	// +optional
	Credentials *cloud.Credentials `json:"credentials,omitempty"`

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

// ClusterIdentityProvider is a cluster-scoped identity provider (Keycloak, a provider with
// dynamic client registration, or a cloud tenant) that the namespaces in allowedNamespaces may claim
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

// GetCloudCommon returns the settings every cloud-capable server kind shares
// (server.CloudServer).
func (s *ClusterIdentityProvider) GetCloudCommon() *common.CloudServerCommon {
	return &s.Spec.CloudServerCommon
}

// GetCredentialsSecret returns the name and the namespace of
// spec.credentials.secretRef, and an empty name for workload identity.
func (s *ClusterIdentityProvider) GetCredentialsSecret() (name, namespace string) {
	return credentialsSecret(s.Spec.Credentials)
}

// GetServerStatus returns the status the probe writes (probe.Server).
func (s *ClusterIdentityProvider) GetServerStatus() *common.ServerStatus {
	return &s.Status.ServerStatus
}

// GetEndpoint returns the server's URL, the Keycloak base URL or the registration
// endpoint; empty for a cloud provider, whose endpoint is the cloud's.
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
