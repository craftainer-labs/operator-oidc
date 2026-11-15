package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// Config is what the reconcilers share.
type Config struct {
	// Client reads providers, Secrets, ConfigMaps and Namespaces. Its Secret and
	// ConfigMap reads must bypass the managed-by cache, which cannot see the
	// admin Secrets and CA bundles of providers.
	Client client.Client
	// OperatorNamespace is where the admin Secret and CA bundle of a cluster
	// provider are read from.
	OperatorNamespace string
	// Egress decides which destinations a provider connection may reach.
	Egress egress.Policy
	// HostDialer builds the dialer of a connection; nil means Egress.HostDialer.
	// Tests replace it, since the policy refuses the loopback address their
	// providers listen on.
	HostDialer func(proxy *url.URL) (egress.DialFunc, error)
	// Cache keeps the client of each provider between reconciles; nil makes a
	// client for every use and closes it when the reconcile is over.
	Cache *ProviderCache
}

// hostDialer is the dialer of a connection to a provider and its proxy.
func (c Config) hostDialer(proxy *url.URL) (egress.DialFunc, error) {
	if c.HostDialer != nil {
		return c.HostDialer(proxy)
	}
	return c.Egress.HostDialer(proxy)
}

// transport is how to reach and trust the provider conn describes. keepAlive is
// for a client that outlives the reconcile.
func (c Config) transport(conn server.Connection, keepAlive bool) (idpclient.Transport, error) {
	dial, err := c.hostDialer(conn.Proxy)
	if err != nil {
		return idpclient.Transport{}, fmt.Errorf("%w: %w", server.ErrInvalidServer, err)
	}
	return idpclient.Transport{
		ServerName: conn.ServerName, CABundle: conn.CABundle, MinTLS: conn.MinTLSVersion, Dial: dial, KeepAlive: keepAlive,
	}, nil
}

// keycloakTarget is the Keycloak realm spec names, reached as the service
// account of the admin Secret in conn.
func keycloakTarget(spec *oidcv1alpha1.ProviderConfig, conn server.Connection, tr idpclient.Transport) (idpclient.KeycloakTarget, error) {
	if spec.Keycloak == nil {
		return idpclient.KeycloakTarget{}, fmt.Errorf("%w: no keycloak block", server.ErrInvalidServer)
	}
	id, secret := conn.Admin[AdminClientIDKey], conn.Admin[AdminClientSecretKey]
	if len(id) == 0 || len(secret) == 0 {
		return idpclient.KeycloakTarget{}, ErrAdminCredentials
	}
	return idpclient.KeycloakTarget{
		Transport: tr, BaseURL: conn.Endpoint, Realm: spec.Keycloak.Realm, ClientID: string(id), ClientSecret: string(secret),
	}, nil
}

// providerOf returns the provider fields of a provider kind of this operator
// and the status it writes its discovery to.
func providerOf(srv server.Server) (*oidcv1alpha1.ProviderConfig, *oidcv1alpha1.IdentityProviderStatus, error) {
	switch s := srv.(type) {
	case *oidcv1alpha1.ClusterIdentityProvider:
		return &s.Spec.ProviderConfig, &s.Status, nil
	case *oidcv1alpha1.IdentityProvider:
		return &s.Spec.ProviderConfig, &s.Status, nil
	}
	return nil, nil, fmt.Errorf("%w: %T", server.ErrUnknownServerKind, srv)
}

// Backend is a resolved provider: its settings and the clients to reach it. The
// clients come from the ProviderCache, so a reconcile calls Release once it is
// done with them.
type Backend struct {
	// Spec is the provider's own fields.
	Spec oidcv1alpha1.ProviderConfig
	// Conn is the connection settings server.Resolve built: the endpoint, the
	// admin credentials, the CA bundle and the proxy.
	Conn server.Connection

	keycloak func() (Conn, func(), error)
	dcr      func() (Conn, func(), error)

	mu     sync.Mutex
	leases []func()
}

// Keycloak returns the client of a provider of type Keycloak.
func (b *Backend) Keycloak() (*idpclient.Keycloak, error) {
	c, err := b.lease(b.keycloak)
	if err != nil {
		return nil, err
	}
	return c.(*idpclient.Keycloak), nil
}

// DCR returns the client of a provider of type DynamicRegistration.
func (b *Backend) DCR() (*idpclient.DCR, error) {
	c, err := b.lease(b.dcr)
	if err != nil {
		return nil, err
	}
	return c.(*idpclient.DCR), nil
}

func (b *Backend) lease(get func() (Conn, func(), error)) (Conn, error) {
	if get == nil {
		return nil, fmt.Errorf("%w: the provider is of type %s", server.ErrInvalidServer, b.Spec.Type)
	}
	c, release, err := get()
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.leases = append(b.leases, release)
	b.mu.Unlock()
	return c, nil
}

// Release gives back every client the reconcile used. The cache closes a client
// it replaced meanwhile only now.
func (b *Backend) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, l := range b.leases {
		l()
	}
	b.leases = nil
}

// providerObject is the part of a provider the controllers use besides its
// connection settings: its identity for the connection cache and its fields.
type providerObject struct {
	uid        types.UID
	generation int64
	spec       oidcv1alpha1.ProviderConfig
}

// fetchProvider reads the provider ref names, which server.Connection does not
// describe fully.
func (c Config) fetchProvider(ctx context.Context, ns string, ref common.ServerRef) (providerObject, error) {
	if ref.Kind == kindClusterIdentityProvider {
		var p oidcv1alpha1.ClusterIdentityProvider
		err := c.Client.Get(ctx, client.ObjectKey{Name: ref.Name}, &p)
		return providerObject{p.UID, p.Generation, p.Spec.ProviderConfig}, err
	}
	var p oidcv1alpha1.IdentityProvider
	err := c.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &p)
	return providerObject{p.UID, p.Generation, p.Spec.ProviderConfig}, err
}

// Backend resolves ref for a claim in ns: the connection settings through
// server.Resolve (which enforces allowedNamespaces), the provider's own fields,
// and clients that dial through the egress policy and the provider's proxy. Its
// errors are coarse: conditions show a fixed text, and the log holds the same.
func (c Config) Backend(ctx context.Context, ns string, ref common.ServerRef) (*Backend, error) {
	key := providerKey(ns, ref)
	conn, err := server.Resolve(ctx, c.Client, ns, ref, server.WithOperatorNamespace(c.OperatorNamespace))
	if err != nil {
		// A provider that is gone or no longer usable keeps no client. A
		// namespace the provider does not serve says nothing about the provider
		// (other namespaces share the entry), so it is not on this list.
		if errors.Is(err, server.ErrServerNotFound) || errors.Is(err, server.ErrInvalidServer) ||
			errors.Is(err, server.ErrAdminSecretNamespaceForbidden) {
			c.Cache.Forget(key)
		}
		return nil, coarse(ctx, "resolve the provider", err)
	}
	obj, err := c.fetchProvider(ctx, ns, ref)
	if err != nil {
		return nil, coarse(ctx, "read the provider", err)
	}
	tr, err := c.transport(conn, true)
	if err != nil {
		return nil, coarse(ctx, "build the dialer", err)
	}
	b := &Backend{Spec: obj.spec, Conn: conn}
	spec := &b.Spec
	switch spec.Type {
	case oidcv1alpha1.ProviderKeycloak:
		target, err := keycloakTarget(spec, conn, tr)
		if err != nil {
			return nil, coarse(ctx, "read the admin Secret", err)
		}
		version := stamp(obj, conn, target.ClientID, target.ClientSecret)
		b.keycloak = func() (Conn, func(), error) {
			cc, release, err := c.Cache.Get(key, version, func() (Conn, error) { return idpclient.NewKeycloak(target) })
			return cc, release, coarse(ctx, "build the Keycloak client", err)
		}
	case oidcv1alpha1.ProviderDynamicRegistration:
		secretNS := ns
		if ref.Kind == kindClusterIdentityProvider {
			secretNS = c.OperatorNamespace
		}
		token, err := c.initialAccessToken(ctx, secretNS, spec.DynamicRegistration)
		if err != nil {
			return nil, coarse(ctx, "read the initial access token", err)
		}
		target := idpclient.DCRTarget{Transport: tr, RegistrationEndpoint: conn.Endpoint, InitialAccessToken: token}
		version := stamp(obj, conn, token)
		b.dcr = func() (Conn, func(), error) {
			cc, release, err := c.Cache.Get(key, version, func() (Conn, error) { return idpclient.NewDCR(target) })
			return cc, release, coarse(ctx, "build the DCR client", err)
		}
	default:
		return nil, coarse(ctx, "read the provider", fmt.Errorf("%w: type %q", server.ErrInvalidServer, spec.Type))
	}
	return b, nil
}

// initialAccessToken reads the token initialAccessTokenSecretRef names, from
// ns, the namespace of the admin Secret (the operator namespace for a cluster
// provider, the provider's own for a namespaced one). It is empty when the
// provider registers clients without one.
func (c Config) initialAccessToken(ctx context.Context, ns string, dcr *oidcv1alpha1.DynamicRegistrationConfig) (string, error) {
	if dcr == nil {
		return "", fmt.Errorf("%w: no dynamicRegistration block", server.ErrInvalidServer)
	}
	ref := dcr.InitialAccessTokenSecretRef
	if ref == nil {
		return "", nil
	}
	var s corev1.Secret
	if err := c.Client.Get(ctx, types.NamespacedName{Namespace: ns, Name: ref.Name}, &s); err != nil {
		return "", err
	}
	if len(s.Data[ref.Key]) == 0 {
		return "", ErrInitialAccessToken
	}
	return string(s.Data[ref.Key]), nil
}

// stamp identifies what a cached client was made from: the provider object (its
// UID and generation) and a hash of everything the client takes from outside it,
// which the generation does not cover: the endpoint, the CA bundle, the proxy
// and the credentials. A changed or rotated credential therefore replaces the
// client. The credentials only go into the hash.
func stamp(o providerObject, conn server.Connection, secrets ...string) string {
	h := sha256.New()
	parts := [][]byte{
		[]byte(conn.Endpoint), conn.CABundle, []byte(conn.ServerName), []byte(strconv.FormatUint(uint64(conn.MinTLSVersion), 10)),
		[]byte(proxyText(conn.Proxy)),
	}
	for _, s := range secrets {
		parts = append(parts, []byte(s))
	}
	for _, part := range parts {
		// Length-prefixed, so ("ab","c") and ("a","bc") differ.
		_, _ = h.Write(strconv.AppendInt(nil, int64(len(part)), 10))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(part)
	}
	return fmt.Sprintf("%s/%d/%s", o.uid, o.generation, hex.EncodeToString(h.Sum(nil)))
}

func proxyText(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}
