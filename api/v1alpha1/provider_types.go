package v1alpha1

import (
	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
)

// ProviderType is how the operator manages clients on the identity provider.
//
// +kubebuilder:validation:Enum=Keycloak;DynamicRegistration;Cognito
type ProviderType string

// Values of ProviderType.
const (
	// ProviderKeycloak manages clients through the Keycloak Admin REST API.
	ProviderKeycloak ProviderType = "Keycloak"
	// ProviderDynamicRegistration manages clients through OAuth 2.0 dynamic
	// client registration (RFC 7591) and its management protocol (RFC 7592).
	ProviderDynamicRegistration ProviderType = "DynamicRegistration"
	// ProviderCognito manages clients as app clients of an existing Amazon
	// Cognito user pool, through the Cognito user pools API.
	ProviderCognito ProviderType = "Cognito"
)

// Scope is one OAuth 2.0 scope token (RFC 6749, section 3.3): printable ASCII
// without space, double quote and backslash.
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=128
// +kubebuilder:validation:Pattern=`^[]-~!#-[]+$`
type Scope string

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=512
// +kubebuilder:validation:XValidation:rule="self.matches('^[]-~!-[]+$')",message="must contain only printable ASCII characters, without spaces or backslashes"
// +kubebuilder:validation:XValidation:rule="self.startsWith('https://') && isURL(self) && url(self).getHostname() != ''",message="must be an https URL with a host"
// +kubebuilder:validation:XValidation:rule="!self.contains('@')",message="must not carry credentials (user@host)"
// +kubebuilder:validation:XValidation:rule="!self.contains('?') && !self.contains('#')",message="must not have a query or a fragment"

// HTTPSURL is an absolute https URL with a host, as the provider kinds'
// URL fields need: printable ASCII without space and backslash, no userinfo
// (@), no query (?) and no fragment (#). The webhooks check the parsed URL
// again.
type HTTPSURL string

// KeycloakConfig is the Keycloak block of a provider of type Keycloak. The
// admin credentials Secret (adminCredentialsSecretRef) holds the keys clientId
// and clientSecret of a service account that may manage clients in the realm.
type KeycloakConfig struct {
	// baseURL is the Keycloak server's https URL, without the realm path.
	BaseURL HTTPSURL `json:"baseURL"`

	// realm is the realm the clients are created in. Only letters, digits,
	// dot, underscore and hyphen are allowed, so the name cannot change the
	// path of an Admin REST call.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._-]+$`
	Realm string `json:"realm"`
}

// SecretKeyRef names one key of a Secret.
type SecretKeyRef struct {
	// name of the Secret. It is in the namespace of the admin credentials
	// Secret: the operator namespace for a cluster provider, the provider's own
	// namespace for a namespaced one.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// key inside the Secret.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key"`
}

// DynamicRegistrationConfig is the block of a provider of type
// DynamicRegistration.
type DynamicRegistrationConfig struct {
	// registrationEndpoint is the https URL clients are registered at
	// (RFC 7591, "registration_endpoint").
	RegistrationEndpoint HTTPSURL `json:"registrationEndpoint"`

	// initialAccessTokenSecretRef names the Secret key holding the initial
	// access token the provider requires for registration. Leave it unset for a
	// provider that registers clients without one.
	//
	// +optional
	InitialAccessTokenSecretRef *SecretKeyRef `json:"initialAccessTokenSecretRef,omitempty"`
}

// CognitoConfig is the block of a provider of type Cognito: the existing user
// pool whose app clients the operator manages. The pool, its hosted-UI domain
// and the IAM permissions of the operator's identity (cognito-idp:
// DescribeUserPool, CreateUserPoolClient, DescribeUserPoolClient,
// UpdateUserPoolClient, DeleteUserPoolClient) are the administrator's: the
// operator creates none of them. The region and role ARN are the common
// provider.aws fields of lib-operator-go (ADR 0002, section 16.1); the
// endpoint override is for emulators and only honoured when the operator runs
// with EGRESS_MODE=allow-private.
type CognitoConfig struct {
	cloud.AWSClusterBlock `json:",inline"`

	// userPoolID is the ID of the user pool, such as eu-west-1_AbCdEf123.
	//
	// +kubebuilder:validation:MaxLength=55
	// +kubebuilder:validation:Pattern=`^[\w-]+_[0-9A-Za-z]+$`
	UserPoolID string `json:"userPoolID"`

	// domain is the pool's hosted-UI domain: the prefix of an Amazon Cognito
	// domain (no dot), or a custom domain (with dots). The authorization,
	// token and user info endpoints of the binding are built from it.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`
	Domain string `json:"domain"`
}

// ProviderConfig is what the two provider kinds share besides the server
// blocks of lib-operator-go. It has no type-level rules: each kind's spec
// carries the rules that differ between the cluster and the namespaced kind.
type ProviderConfig struct {
	// type is how clients are managed. It cannot change after creation.
	//
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="type is immutable"
	Type ProviderType `json:"type"`

	// issuer is the provider's https issuer URL (the "iss" of its tokens). It
	// is required for Keycloak and DynamicRegistration and forbidden for
	// Cognito, whose issuer the operator derives from the pool.
	//
	// +optional
	Issuer HTTPSURL `json:"issuer,omitempty"`

	// keycloak is required when type is Keycloak and forbidden otherwise.
	//
	// +optional
	Keycloak *KeycloakConfig `json:"keycloak,omitempty"`

	// dynamicRegistration is required when type is DynamicRegistration and
	// forbidden otherwise.
	//
	// +optional
	DynamicRegistration *DynamicRegistrationConfig `json:"dynamicRegistration,omitempty"`

	// cognito is required when type is Cognito and forbidden otherwise. The
	// cloud credentials of the operator are the provider's credentials field.
	//
	// +optional
	Cognito *CognitoConfig `json:"cognito,omitempty"`

	// allowedScopes limits the scopes a client may request.
	//
	// +kubebuilder:default={"openid","profile","email"}
	// +kubebuilder:validation:MaxItems=50
	// +listType=set
	// +optional
	AllowedScopes []Scope `json:"allowedScopes,omitempty"`
}

// Endpoint returns the provider's own URL: the Keycloak base URL, or the
// registration endpoint. It is what a provider kind's GetEndpoint returns.
func (c *ProviderConfig) Endpoint() string {
	switch {
	case c.Type == ProviderKeycloak && c.Keycloak != nil:
		return string(c.Keycloak.BaseURL)
	case c.Type == ProviderDynamicRegistration && c.DynamicRegistration != nil:
		return string(c.DynamicRegistration.RegistrationEndpoint)
	default:
		return ""
	}
}

// Discovery is what the provider's /.well-known/openid-configuration document
// reported, copied into the binding of every client that uses the provider.
type Discovery struct {
	// tokenEndpoint is "token_endpoint".
	//
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	TokenEndpoint string `json:"tokenEndpoint,omitempty"`

	// authorizationEndpoint is "authorization_endpoint".
	//
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`

	// jwksUri is "jwks_uri".
	//
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	JWKSURI string `json:"jwksUri,omitempty"`

	// userinfoEndpoint is "userinfo_endpoint".
	//
	// +kubebuilder:validation:MaxLength=2048
	// +optional
	UserinfoEndpoint string `json:"userinfoEndpoint,omitempty"`
}

// IdentityProviderStatus is the status of both provider kinds: the common
// server status plus the discovered endpoints.
type IdentityProviderStatus struct {
	common.ServerStatus `json:",inline"`

	// discovery is what the provider's discovery document reported at the last
	// successful probe.
	//
	// +optional
	Discovery *Discovery `json:"discovery,omitempty"`
}

// credentialsSecret is the Secret credentials names, or empty for workload
// identity or no credentials.
func credentialsSecret(c *cloud.Credentials) (name, namespace string) {
	if c == nil || c.Source != cloud.SourceSecret || c.SecretRef == nil {
		return "", ""
	}
	return c.SecretRef.Name, c.SecretRef.Namespace
}
