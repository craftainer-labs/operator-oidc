package controller

import (
	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
)

// The two provider kinds a claim may name.
const (
	kindClusterIdentityProvider = "ClusterIdentityProvider"
	kindIdentityProvider        = "IdentityProvider"
)

// providerKey names a provider in the connection cache: a cluster provider is
// one entry for every namespace, a namespaced one is one per namespace.
func providerKey(namespace string, ref common.ServerRef) string {
	if ref.Kind == kindClusterIdentityProvider {
		namespace = ""
	}
	return ref.Kind + "/" + namespace + "/" + ref.Name
}
