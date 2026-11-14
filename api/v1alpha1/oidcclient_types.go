package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
)

// GrantType is an OAuth 2.0 grant a client may use.
//
// +kubebuilder:validation:Enum=authorization_code;refresh_token;client_credentials
type GrantType string

// Values of GrantType.
const (
	// GrantAuthorizationCode is the authorization code grant (with PKCE).
	GrantAuthorizationCode GrantType = "authorization_code"
	// GrantRefreshToken is the refresh token grant.
	GrantRefreshToken GrantType = "refresh_token"
	// GrantClientCredentials is the client credentials grant. It needs a
	// confidential client.
	GrantClientCredentials GrantType = "client_credentials"
)

// TokenEndpointAuthMethod is how the client authenticates at the token
// endpoint.
//
// +kubebuilder:validation:Enum=client_secret_basic;client_secret_post;none
type TokenEndpointAuthMethod string

// Values of TokenEndpointAuthMethod.
const (
	// AuthMethodClientSecretBasic sends the secret in an HTTP Basic header.
	AuthMethodClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	// AuthMethodClientSecretPost sends the secret in the request body.
	AuthMethodClientSecretPost TokenEndpointAuthMethod = "client_secret_post"
	// AuthMethodNone is for a public client: it has no secret.
	AuthMethodNone TokenEndpointAuthMethod = "none"
)

// PKCEMode says whether the provider enforces PKCE (RFC 7636).
//
// +kubebuilder:validation:Enum=S256;Disabled
type PKCEMode string

// Values of PKCEMode.
const (
	// PKCES256 requires the S256 code challenge method.
	PKCES256 PKCEMode = "S256"
	// PKCEDisabled does not require PKCE. A public client cannot use it.
	PKCEDisabled PKCEMode = "Disabled"
)

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=2048
// +kubebuilder:validation:XValidation:rule="self.matches('^[]-~!-[]+$')",message="must contain only printable ASCII characters, without spaces or backslashes"
// +kubebuilder:validation:XValidation:rule="self.startsWith('https://') || self.startsWith('http://')",message="must start with https://, or with http:// for localhost or 127.0.0.1"
// +kubebuilder:validation:XValidation:rule="!self.contains('*')",message="wildcards are not allowed"
// +kubebuilder:validation:XValidation:rule="!self.contains('#')",message="a fragment is not allowed"
// +kubebuilder:validation:XValidation:rule="!self.contains('@')",message="userinfo (user@host) is not allowed"
// +kubebuilder:validation:XValidation:rule="isURL(self) && url(self).getHostname() != ''",message="must be an absolute URL with a host"
// +kubebuilder:validation:XValidation:rule="!self.startsWith('http://') || url(self).getHostname() in ['localhost', '127.0.0.1']",message="an http URI must have the host localhost or 127.0.0.1 exactly"

// RedirectURI is a redirect or post-logout redirect URI. It is an exact URI,
// never a pattern: https, or http only for the loopback hosts localhost and
// 127.0.0.1 (which a public client alone may use, see the OidcClientSpec rules);
// no wildcard, no fragment and no userinfo. The rules compare the parsed host
// exactly, because a prefix or regex match would accept
// http://localhost.evil.example. The webhook parses the URI again.
type RedirectURI string

// WebOrigin is an origin allowed to call the client's endpoints from a browser
// (CORS): https://host[:port], or http://localhost or http://127.0.0.1 for a
// public client. No path, no wildcard and no "+" (Keycloak's "all redirect
// origins").
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=300
// +kubebuilder:validation:XValidation:rule="self.matches('^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$') || self.matches('^http://(localhost|127[.]0[.]0[.]1)(:[0-9]{1,5})?$')",message="must be an origin: https://host[:port], or http://localhost or http://127.0.0.1 with an optional port, without a path or wildcard"
type WebOrigin string

// OidcClientSpec defines the desired state of OidcClient. It is a credential
// kind: it has no deletionPolicy (the client is always deleted with the claim)
// and a confidential client's secret is written to a binding Secret.
//
// +kubebuilder:validation:XValidation:rule="self.serverRef.kind in ['ClusterIdentityProvider', 'IdentityProvider']",message="serverRef.kind must be ClusterIdentityProvider or IdentityProvider"
// +kubebuilder:validation:XValidation:rule="!has(self.rotationPolicy) || self.managementPolicies == ['*'] || 'Update' in self.managementPolicies",message="rotationPolicy needs the Update management policy"
// +kubebuilder:validation:XValidation:rule="!has(self.rotationPolicy) || !self.public",message="rotationPolicy is allowed only on a confidential client: a public client has no secret to rotate"
// +kubebuilder:validation:XValidation:rule="!self.public || !('client_credentials' in self.grantTypes)",message="the client_credentials grant needs a confidential client (public: false)"
// +kubebuilder:validation:XValidation:rule="!has(self.tokenEndpointAuthMethod) || (self.tokenEndpointAuthMethod == 'none') == self.public",message="tokenEndpointAuthMethod none is for public clients and only for them"
// +kubebuilder:validation:XValidation:rule="!self.public || self.pkce != 'Disabled'",message="a public client must use PKCE: pkce Disabled is not allowed"
// +kubebuilder:validation:XValidation:rule="self.public || (!self.redirectUris.exists(u, u.startsWith('http://')) && (!has(self.postLogoutRedirectUris) || !self.postLogoutRedirectUris.exists(u, u.startsWith('http://'))) && (!has(self.webOrigins) || !self.webOrigins.exists(o, o.startsWith('http://'))))",message="an http loopback URI or origin is allowed only on a public client (public: true); a confidential client needs https"
type OidcClientSpec struct {
	common.ClaimCommon `json:",inline"`
	common.Credentials `json:",inline"`

	// public makes the client a public one (a native or single-page app): it
	// has no secret, so no binding Secret holds a clientSecret.
	//
	// +kubebuilder:default=false
	// +optional
	Public bool `json:"public,omitempty"`

	// redirectUris are the exact URIs the provider may redirect to after login.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=20
	// +listType=set
	RedirectURIs []RedirectURI `json:"redirectUris"`

	// postLogoutRedirectUris are the exact URIs the provider may redirect to
	// after logout, with the same rules as redirectUris.
	//
	// +kubebuilder:validation:MaxItems=20
	// +listType=set
	// +optional
	PostLogoutRedirectURIs []RedirectURI `json:"postLogoutRedirectUris,omitempty"`

	// webOrigins are the origins allowed to call the client's endpoints from a
	// browser.
	//
	// +kubebuilder:validation:MaxItems=20
	// +listType=set
	// +optional
	WebOrigins []WebOrigin `json:"webOrigins,omitempty"`

	// grantTypes are the grants the client may use.
	//
	// +kubebuilder:default={"authorization_code"}
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=3
	// +listType=set
	// +optional
	GrantTypes []GrantType `json:"grantTypes,omitempty"`

	// tokenEndpointAuthMethod is how the client authenticates at the token
	// endpoint. It is "none" for a public client and "client_secret_basic"
	// for a confidential one when unset (the operator resolves it; there is no
	// schema default, because the default depends on public).
	//
	// +optional
	TokenEndpointAuthMethod TokenEndpointAuthMethod `json:"tokenEndpointAuthMethod,omitempty"`

	// pkce says whether PKCE is required.
	//
	// +kubebuilder:default=S256
	// +optional
	PKCE PKCEMode `json:"pkce,omitempty"`

	// scopes are the scopes the client may request. Each must be one of the
	// provider's allowedScopes (the controller checks that).
	//
	// +kubebuilder:default={"openid"}
	// +kubebuilder:validation:MaxItems=50
	// +listType=set
	// +optional
	Scopes []Scope `json:"scopes,omitempty"`
}

// OidcClientStatus defines the observed state of OidcClient.
type OidcClientStatus struct {
	common.ClaimStatus       `json:",inline"`
	common.CredentialsStatus `json:",inline"`

	// registrationClientUri is the client's management URI after dynamic
	// registration (RFC 7592). The registration access token is in a Secret in
	// the operator namespace, never in status.
	//
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	RegistrationClientURI string `json:"registrationClientUri,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=craftainer
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.serverRef.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OidcClient is an OpenID Connect client registered with an identity provider,
// its credentials written to a binding Secret.
type OidcClient struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of OidcClient
	// +required
	Spec OidcClientSpec `json:"spec"`

	// status defines the observed state of OidcClient
	// +optional
	Status OidcClientStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// OidcClientList contains a list of OidcClient.
type OidcClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []OidcClient `json:"items"`
}

// The methods below implement lib-operator-go's lifecycle.Claim.

// GetServerRef returns spec.serverRef.
func (u *OidcClient) GetServerRef() common.ServerRef { return u.Spec.ServerRef }

// GetDeletionPolicy returns "": a user is always deleted with its claim.
func (u *OidcClient) GetDeletionPolicy() common.DeletionPolicy { return "" }

// GetManagementPolicies returns spec.managementPolicies.
func (u *OidcClient) GetManagementPolicies() []common.ManagementPolicy {
	return u.Spec.ManagementPolicies
}

// GetConditions returns status.conditions.
func (u *OidcClient) GetConditions() *[]metav1.Condition { return &u.Status.Conditions }

// GetBindingSecretName returns spec.binding.secretName, or the claim's name.
func (u *OidcClient) GetBindingSecretName() string {
	if u.Spec.Binding.SecretName != "" {
		return u.Spec.Binding.SecretName
	}
	return u.Name
}

// SetBindingName sets status.binding.name.
func (u *OidcClient) SetBindingName(v string) { u.Status.Binding = &common.BindingStatus{Name: v} }

// GetExternalName returns status.externalName.
func (u *OidcClient) GetExternalName() string { return u.Status.ExternalName }

// SetExternalName sets status.externalName.
func (u *OidcClient) SetExternalName(v string) { u.Status.ExternalName = v }

// GetExternalID returns status.externalId.
func (u *OidcClient) GetExternalID() string { return u.Status.ExternalID }

// SetExternalID sets status.externalId.
func (u *OidcClient) SetExternalID(v string) { u.Status.ExternalID = v }

// SetObservedGeneration sets status.observedGeneration.
func (u *OidcClient) SetObservedGeneration(v int64) { u.Status.ObservedGeneration = v }

// SetLastReconcileTime sets status.lastReconcileTime.
func (u *OidcClient) SetLastReconcileTime(v metav1.Time) { u.Status.LastReconcileTime = &v }

// GetEffectiveDeletionPolicy returns "": a user has no pinned policy.
func (u *OidcClient) GetEffectiveDeletionPolicy() common.DeletionPolicy { return "" }

// SetEffectiveDeletionPolicy does nothing: a user has no pinned policy.
func (u *OidcClient) SetEffectiveDeletionPolicy(common.DeletionPolicy, common.DeletionPolicySource) {
}

// SetLateInitialized sets status.lateInitialized.
func (u *OidcClient) SetLateInitialized(v map[string]string) { u.Status.LateInitialized = v }

// GetRotationPolicy returns spec.rotationPolicy.
func (u *OidcClient) GetRotationPolicy() *common.RotationPolicy { return u.Spec.RotationPolicy }

// GetRotationStatus returns status.rotation, or the zero status.
func (u *OidcClient) GetRotationStatus() common.RotationStatus {
	if u.Status.Rotation == nil {
		return common.RotationStatus{}
	}
	return *u.Status.Rotation
}

// SetRotationStatus sets status.rotation.
func (u *OidcClient) SetRotationStatus(v common.RotationStatus) { u.Status.Rotation = &v }

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &OidcClient{}, &OidcClientList{})
		return nil
	})
}
