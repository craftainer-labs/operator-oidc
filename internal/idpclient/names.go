package idpclient

import (
	"github.com/craftainer-labs/lib-operator-go/pkg/naming"
)

// maxClientNameLen is the cap of both names below (ADR 0002 section 10): the
// Keycloak CLIENT_ID column holds 255 characters, and a registered client's
// name is free text for which 255 is our own cap.
const maxClientNameLen = 255

// KeycloakClientID is the client_id of an OidcClient on Keycloak. A Keycloak
// client can hold the ownership marker (an attribute), so the name carries the
// short hash.
func KeycloakClientID(ns, name string) string {
	return naming.Tenant(ns, name, maxClientNameLen, "-", naming.HashShort)
}

// DCRClientName is the client_name an OidcClient registers with. A registered
// client cannot hold a marker, and the name is not what finds it (the client_id
// the provider assigned is), so the name carries the long hash only to keep the
// rule mechanical for every markerless object.
func DCRClientName(ns, name string) string {
	return naming.Tenant(ns, name, maxClientNameLen, "-", naming.HashLong)
}

// Marker is the ownership marker of a claim, "<namespace>/<name>/<uid>": the
// value of the Keycloak client attribute craftainer.dev/claim.
func Marker(ns, name, uid string) string {
	return ns + "/" + name + "/" + uid
}

// maxCognitoClientNameLen is the longest app client name Cognito accepts.
const maxCognitoClientNameLen = 128

// CognitoClientName is the name of the Cognito app client of an OidcClient.
// An app client has no tag or description to hold an ownership marker, and the
// client ID Cognito assigns is what finds it, so the name is only a label: it
// carries the short hash, as ADR 0002 section 16.6 says.
func CognitoClientName(ns, name string) string {
	return naming.Tenant(ns, name, maxCognitoClientNameLen, "-", naming.HashShort)
}
