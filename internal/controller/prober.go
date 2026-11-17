package controller

import (
	"context"
	"net/url"

	"github.com/craftainer-labs/lib-operator-go/pkg/probe"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// Prober is the probe.CloudProber of both provider kinds. A provider is healthy
// when it answers its discovery document at the issuer and, for Keycloak,
// accepts the admin service account too (one authenticated request to the
// realm's clients). A provider of type DynamicRegistration needs no more:
// registering a client to try it would leave one behind, and the initial access
// token can only be proved by using it. The probe records the discovery
// document's endpoints in status.discovery.
//
// A provider of type Cognito is healthy when its user pool can be described
// with the operator's cloud credentials (the Cognito API, not the hosted UI:
// the endpoints of status.discovery follow from the configuration). The probe
// records the pool in status.discovered; a failure shows through the
// library's own reasons.
//
// A provider of type Entra is healthy when the operator's identity gets a
// Graph token and may list the applications it owns (the permission it needs
// anyway, Application.ReadWrite.OwnedBy). The probe records the tenant and the
// authority host in status.discovered; the endpoints of status.discovery follow
// from the tenant ID.
//
// It builds its clients through the egress policy and the provider's own proxy
// and TLS settings, with connections of their own: it never takes a client from
// the claims' ProviderCache and never puts one there, so a probe can neither pin
// nor evict a cached client.
//
// The caller (probe.Reconciler) bounds a probe by Options.Timeout and logs the
// error it returns, so the error is category-only: a fixed text per kind of
// failure, never the address, the credentials or the provider's own words.
type Prober struct {
	Config Config
}

var _ probe.CloudProber = Prober{}

// ProbeCloud checks the provider srv names. It returns no version: neither
// Keycloak (its Admin REST API reports it only to a master-realm administrator),
// nor a dynamic registration provider, nor Cognito tells a client of one.
func (p Prober) ProbeCloud(ctx context.Context, srv server.CloudServer, conn server.CloudConnection) (probe.CloudResult, error) {
	ref, err := providerOf(srv)
	if err != nil {
		return probe.CloudResult{}, categoryOnly(err)
	}
	if ref.spec.Type == oidcv1alpha1.ProviderCognito {
		disc, err := p.Config.discoverCognito(ctx, ref, conn)
		if err != nil {
			return probe.CloudResult{}, categoryOnly(err)
		}
		record(ref.status, cognitoDiscovery(ref.spec.Cognito))
		return probe.CloudResult{Discovered: disc}, nil
	}
	if ref.spec.Type == oidcv1alpha1.ProviderEntra {
		disc, err := p.Config.discoverEntra(ctx, ref, conn)
		if err != nil {
			return probe.CloudResult{}, categoryOnly(err)
		}
		record(ref.status, entraDiscovery(ref.spec.Entra))
		return probe.CloudResult{Discovered: disc}, nil
	}
	return probe.CloudResult{}, p.probeDiscovery(ctx, ref, conn.Connection)
}

// probeDiscovery probes a Keycloak or dynamic registration provider.
func (p Prober) probeDiscovery(ctx context.Context, ref providerRef, conn server.Connection) error {
	spec, status := ref.spec, ref.status
	tr, err := p.Config.transport(conn, false)
	if err != nil {
		return categoryOnly(err)
	}
	if spec.Type == oidcv1alpha1.ProviderKeycloak {
		target, err := keycloakTarget(spec, conn, tr)
		if err != nil {
			return categoryOnly(err)
		}
		k, err := idpclient.NewKeycloak(target)
		if err != nil {
			return categoryOnly(err)
		}
		if err := k.Probe(ctx); err != nil {
			return categoryOnly(err)
		}
	}
	// The server name override is for the host the admin credentials go to;
	// an issuer on another host is verified by its own name.
	if hostOf(string(spec.Issuer)) != hostOf(conn.Endpoint) {
		tr.ServerName = ""
	}
	d, err := idpclient.Discover(ctx, tr, string(spec.Issuer))
	if err != nil {
		return categoryOnly(err)
	}
	record(status, &oidcv1alpha1.Discovery{
		TokenEndpoint: d.TokenEndpoint, AuthorizationEndpoint: d.AuthorizationEndpoint,
		JWKSURI: d.JWKSURI, UserinfoEndpoint: d.UserinfoEndpoint,
	})
	return nil
}

// record sets status.discovery. The probe helper writes the status only when
// its own fields changed, so a changed discovery document clears lastProbeTime:
// that is a change the helper cannot miss, and it sets lastProbeTime again.
func record(status *oidcv1alpha1.IdentityProviderStatus, d *oidcv1alpha1.Discovery) {
	if status.Discovery != nil && *status.Discovery == *d {
		return
	}
	status.Discovery = d
	status.LastProbeTime = nil
}

// hostOf is the host and port of a URL, "" for one that does not parse.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
