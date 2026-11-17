package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
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
	// EgressMode is the mode Egress was built from; the cloud clients use it
	// to decide whether endpointOverride is honoured.
	EgressMode egress.Mode
	// Cognito builds the Cognito client of a Cognito provider (NewCognito
	// when nil). Tests replace it.
	Cognito func(aws.Config) CognitoAPI
	// Entra builds the Microsoft Graph client of an Entra provider (NewGraph
	// when nil). Tests replace it.
	Entra func(*cloud.AzureClient) (GraphAPI, error)
	// RootCAs are the roots the Azure clients (Graph and the authority) trust;
	// nil means the system roots. Only tests whose fake endpoint has its own
	// certificate set it: no flag or environment variable reaches it.
	RootCAs *x509.CertPool
	// HostDialer builds the dialer of a connection; nil means Egress.HostDialer.
	// Tests replace it, since the policy refuses the loopback address their
	// providers listen on.
	HostDialer func(proxy *url.URL) (egress.DialFunc, error)
	// Cache keeps the client of each provider between reconciles; nil makes a
	// client for every use and closes it when the reconcile is over.
	Cache *ProviderCache
	// APIReader looks for binding Secrets (lifecycle.Options.APIReader): the
	// operator's Secret cache holds only the Secrets it labelled. nil uses
	// Client.
	APIReader client.Reader
	// Recorder emits the Events of the OidcClient controller. Required by it.
	Recorder events.EventRecorder
	// ManagedBy is the managed-by label of binding and registration Secrets.
	ManagedBy string
	// MaxConcurrentReconciles is how many OidcClients reconcile at once; below
	// 1 means 1.
	MaxConcurrentReconciles int
	// Now is the clock of the lifecycle (rotation and grace periods); nil is
	// time.Now. Tests advance it.
	Now func() time.Time
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

// providerRef is the parts of a provider of this operator that the probe and
// the claims use: its own fields, the status it writes its discovery to, and
// how it reaches the cloud.
type providerRef struct {
	spec   *oidcv1alpha1.ProviderConfig
	status *oidcv1alpha1.IdentityProviderStatus
	// scope and creds are the arguments of cloud.Egress.AWS: a namespaced
	// provider has no workload identity.
	scope cloud.Scope
	creds *cloud.Credentials
}

// providerOf returns the provider fields of a provider kind of this operator.
func providerOf(srv server.CloudServer) (providerRef, error) {
	switch s := srv.(type) {
	case *oidcv1alpha1.ClusterIdentityProvider:
		return providerRef{spec: &s.Spec.ProviderConfig, status: &s.Status, scope: cloud.ScopeCluster, creds: s.Spec.Credentials}, nil
	case *oidcv1alpha1.IdentityProvider:
		return providerRef{spec: &s.Spec.ProviderConfig, status: &s.Status, scope: cloud.ScopeNamespaced, creds: s.Spec.Credentials.AsCredentials()}, nil
	}
	return providerRef{}, fmt.Errorf("%w: %T", server.ErrUnknownServerKind, srv)
}

// Backend is a resolved provider: its settings and the clients to reach it. The
// clients come from the ProviderCache, so a reconcile calls Release once it is
// done with them.
type Backend struct {
	// Spec is the provider's own fields.
	Spec oidcv1alpha1.ProviderConfig
	// Conn is the connection settings server.ResolveCloud built: the endpoint,
	// the admin credentials, the CA bundle and the proxy.
	Conn server.Connection
	// Issuer is the issuer of the provider's tokens: spec.issuer, or for
	// Cognito the one derived from the user pool.
	Issuer string
	// UserPoolID is the user pool of a Cognito provider.
	UserPoolID string
	// Discovery is what the provider's last successful probe found; nil before
	// one.
	Discovery *oidcv1alpha1.Discovery

	keycloak func() (Conn, func(), error)
	dcr      func() (Conn, func(), error)
	cognito  func() (Conn, func(), error)
	entra    func() (Conn, func(), error)

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

// Cognito returns the client of a provider of type Cognito. Unlike the other
// providers' clients it is not cached: building it retrieves the cloud
// credentials, which must not happen with the cache's lock held.
func (b *Backend) Cognito() (CognitoAPI, error) {
	c, err := b.lease(b.cognito)
	if err != nil {
		return nil, err
	}
	return c.(*cognitoClient), nil
}

// Entra returns the Graph client of a provider of type Entra. It is not cached,
// for the reason Cognito is not.
func (b *Backend) Entra() (GraphAPI, error) {
	c, err := b.lease(b.entra)
	if err != nil {
		return nil, err
	}
	return c.(*entraClient), nil
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
	discovery  *oidcv1alpha1.Discovery
	scope      cloud.Scope
	creds      *cloud.Credentials
}

// fetchProvider reads the provider ref names, which server.Connection does not
// describe fully.
func (c Config) fetchProvider(ctx context.Context, ns string, ref common.ServerRef) (providerObject, error) {
	if ref.Kind == kindClusterIdentityProvider {
		var p oidcv1alpha1.ClusterIdentityProvider
		err := c.Client.Get(ctx, client.ObjectKey{Name: ref.Name}, &p)
		return providerObject{uid: p.UID, generation: p.Generation, spec: p.Spec.ProviderConfig, discovery: p.Status.Discovery,
			scope: cloud.ScopeCluster, creds: p.Spec.Credentials}, err
	}
	var p oidcv1alpha1.IdentityProvider
	err := c.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &p)
	return providerObject{uid: p.UID, generation: p.Generation, spec: p.Spec.ProviderConfig, discovery: p.Status.Discovery,
		scope: cloud.ScopeNamespaced, creds: p.Spec.Credentials.AsCredentials()}, err
}

// Backend resolves ref for a claim in ns: the connection settings through
// server.Resolve (which enforces allowedNamespaces), the provider's own fields,
// and clients that dial through the egress policy and the provider's proxy. Its
// errors are coarse: conditions show a fixed text, and the log holds the same.
func (c Config) Backend(ctx context.Context, ns string, ref common.ServerRef) (*Backend, error) {
	key := providerKey(ns, ref)
	cc, err := server.ResolveCloud(ctx, c.Client, ns, ref, server.WithOperatorNamespace(c.OperatorNamespace))
	conn := cc.Connection
	if err != nil {
		// A provider that is gone or no longer usable keeps no client. A
		// namespace the provider does not serve says nothing about the provider
		// (other namespaces share the entry), so it is not on this list.
		if errors.Is(err, server.ErrServerNotFound) || errors.Is(err, server.ErrInvalidServer) ||
			errors.Is(err, server.ErrAdminSecretNamespaceForbidden) ||
			errors.Is(err, server.ErrCredentialsSecretNamespaceForbidden) || errors.Is(err, server.ErrCredentialsUnavailable) {
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
	b := &Backend{Spec: obj.spec, Conn: conn, Discovery: obj.discovery, Issuer: string(obj.spec.Issuer)}
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
	case oidcv1alpha1.ProviderCognito:
		cg := spec.Cognito
		if cg == nil {
			return nil, coarse(ctx, "read the provider", fmt.Errorf("%w: no cognito block", server.ErrInvalidServer))
		}
		// The endpoints and the issuer follow from the configuration, so a
		// client does not wait for the first probe.
		b.Issuer, b.UserPoolID, b.Discovery = cognitoIssuer(cg), cg.UserPoolID, cognitoDiscovery(cg)
		b.cognito = func() (Conn, func(), error) {
			cl, err := c.newCognito(ctx, cg, obj.scope, obj.creds, cc)
			if err != nil {
				return nil, nil, coarse(ctx, "build the Cognito client", err)
			}
			return cl, cl.CloseIdleConnections, nil
		}
	case oidcv1alpha1.ProviderEntra:
		en := spec.Entra
		if en == nil {
			return nil, coarse(ctx, "read the provider", fmt.Errorf("%w: no entra block", server.ErrInvalidServer))
		}
		// The endpoints and the issuer follow from the tenant, so a client does
		// not wait for the first probe.
		b.Issuer, b.Discovery = entraIssuer(en), entraDiscovery(en)
		b.entra = func() (Conn, func(), error) {
			cl, err := c.newEntra(ctx, en, obj.scope, obj.creds, cc)
			if err != nil {
				return nil, nil, coarse(ctx, "build the Graph client", err)
			}
			return cl, cl.CloseIdleConnections, nil
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
