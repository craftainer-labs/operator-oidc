package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// entraAuthority is the Entra authority host of the public cloud.
const entraAuthority = "https://login.microsoftonline.com"

var (
	// ErrEntraSecret means the claim's confidential or public type differs from
	// the application's: the operator does not turn one into the other.
	ErrEntraSecret = errors.New("an Entra application is not changed between public and confidential: delete the claim and create it again")
	// ErrEntraLogout means the claim lists more post-logout redirect URIs than
	// an Entra application has fields for.
	ErrEntraLogout = errors.New("an Entra application has one logout URL: postLogoutRedirectURIs may list at most one")
	// ErrEntraScope means the claim asks for a scope that is not an OIDC scope.
	ErrEntraScope = errors.New("an Entra application supports only the OIDC scopes openid, profile, email and offline_access")
)

// entraScopes are the scopes an Entra application grants without an API
// permission: the OIDC scopes of the Microsoft identity platform.
var entraScopes = []string{"openid", "profile", "email", "offline_access"}

// GraphAPI is the part of the Microsoft Graph client the operator uses
// (*idpclient.Graph).
type GraphAPI interface {
	Probe(ctx context.Context) error
	Get(ctx context.Context, id string) (idpclient.GraphApp, error)
	Create(ctx context.Context, a idpclient.GraphApp) (idpclient.GraphApp, error)
	Update(ctx context.Context, id string, a idpclient.GraphApp) error
	Delete(ctx context.Context, id string) error
	AddPassword(ctx context.Context, id, name string) (idpclient.GraphSecret, error)
	RemovePassword(ctx context.Context, id, keyID string) error
}

var _ GraphAPI = (*idpclient.Graph)(nil)

// NewGraph builds the Graph client of an Azure client, whose HTTP client dials
// through the egress policy (cloud.Egress.Azure) and whose credential fetches
// the Graph token. With an endpointOverride the Graph host is the override too.
func NewGraph(az *cloud.AzureClient) (GraphAPI, error) {
	hc, ok := az.ClientOptions.Transport.(*http.Client)
	if !ok {
		return nil, cloudErr("the cloud credentials are unavailable")
	}
	base := idpclient.GraphBase
	if az.Endpoint != "" {
		base = strings.TrimRight(az.Endpoint, "/")
	}
	src := cloud.AzureTokenSource(az.Credential, idpclient.GraphScope)
	g, err := idpclient.NewGraph(hc, base, func(ctx context.Context) (string, error) {
		tok, _, err := src.Token(ctx)
		return tok, err
	})
	if err != nil {
		return nil, cloudErr("endpointOverride is not allowed here")
	}
	return g, nil
}

// entraClient is a GraphAPI that can close its idle connections.
type entraClient struct {
	GraphAPI
	hc *http.Client
}

// CloseIdleConnections releases the connections of the client's HTTP client.
func (c *entraClient) CloseIdleConnections() {
	if c.hc != nil {
		c.hc.CloseIdleConnections()
	}
}

// newEntra builds the client of an Entra provider with the operator's
// credentials to the cloud (workload identity, or the Secret conn carries).
// Every HTTP connection dials through the egress policy and the provider's
// proxy.
func (c Config) newEntra(ctx context.Context, en *oidcv1alpha1.EntraConfig, scope cloud.Scope, creds *cloud.Credentials, conn server.CloudConnection) (*entraClient, error) {
	e := cloud.Egress{Mode: c.EgressMode, Policy: c.Egress, Proxy: conn.Proxy, RootCAs: c.RootCAs}
	az, err := e.Azure(ctx, scope, en.AzureClusterBlock, creds, conn.Credentials)
	if err != nil {
		return nil, cloudConfigErr(err)
	}
	factory := c.Entra
	if factory == nil {
		factory = NewGraph
	}
	api, err := factory(az)
	if err != nil {
		return nil, err
	}
	hc, _ := az.ClientOptions.Transport.(*http.Client)
	return &entraClient{GraphAPI: api, hc: hc}, nil
}

// entraAuthorityOf is the Entra authority host: the public cloud's, or the
// endpointOverride of a cluster provider.
func entraAuthorityOf(en *oidcv1alpha1.EntraConfig) string {
	if en.EndpointOverride != "" {
		return strings.TrimRight(en.EndpointOverride, "/")
	}
	return entraAuthority
}

// entraIssuer is the issuer of the tenant's v2.0 tokens.
func entraIssuer(en *oidcv1alpha1.EntraConfig) string {
	return entraAuthorityOf(en) + "/" + en.TenantID + "/v2.0"
}

// entraDiscovery is the endpoints of a tenant, derived from its ID: the
// authority serves the authorization and token endpoints and the signing keys,
// Graph the user info endpoint.
func entraDiscovery(en *oidcv1alpha1.EntraConfig) *oidcv1alpha1.Discovery {
	a := entraAuthorityOf(en) + "/" + en.TenantID
	graph := idpclient.GraphBase
	if en.EndpointOverride != "" {
		graph = entraAuthorityOf(en)
	}
	return &oidcv1alpha1.Discovery{
		AuthorizationEndpoint: a + "/oauth2/v2.0/authorize", TokenEndpoint: a + "/oauth2/v2.0/token",
		JWKSURI: a + "/discovery/v2.0/keys", UserinfoEndpoint: graph + "/oidc/userinfo",
	}
}

// entraErr classifies a failed Graph call: a token that could not be fetched
// is the credentials' failure; throttling, timeouts and 5xx answers are
// transient (the provider is unreachable for now). Anything else is returned as
// it is: a missing application stays idpclient.ErrNotFound, a refused request
// and a failed connection have their own fixed texts.
func entraErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, idpclient.ErrGraphToken) {
		return cloudErr("the cloud credentials are unavailable")
	}
	var se *idpclient.Error
	if errors.As(err, &se) && transientCause(nil, se.Status) {
		return &CloudError{msg: "the Graph API call failed", transient: true}
	}
	return err
}

// discoverEntra probes the tenant of an Entra provider: it gets a token and
// lists at most one application the identity owns (Graph permission
// Application.ReadWrite.OwnedBy, which the operator needs anyway), and returns
// what it found for status.discovered. The errors are category-only.
func (c Config) discoverEntra(ctx context.Context, ref providerRef, conn server.CloudConnection) (map[string]string, error) {
	en := ref.spec.Entra
	if en == nil {
		return nil, cloudErr("the provider has no entra block")
	}
	cl, err := c.newEntra(ctx, en, ref.scope, ref.creds, conn)
	if err != nil {
		return nil, err
	}
	// The client is built for this call: release its idle connections after it.
	defer cl.CloseIdleConnections()
	if err := cl.Probe(ctx); err != nil {
		return nil, entraErr(err)
	}
	return map[string]string{discoveredResourceID: en.TenantID, discoveredEndpoint: hostOf(entraAuthorityOf(en))}, nil
}

// entraState is what Observe read of an application. The secret of a
// confidential application cannot be read again: only whether it has one.
type entraState struct {
	// ID is the object ID, AppID the application (client) ID.
	ID, AppID string
	// Public is isFallbackPublicClient; HasSecret says the application holds a
	// client secret.
	Public, HasSecret bool
}

// entraDriver manages an application registration of a tenant.
// status.externalName is the display name and status.externalId the object ID
// Graph assigned: an application carries no ownership marker the operator may
// rely on (ADR 0004), so it is found by the object ID only, and an application
// the status never recorded is not adopted.
type entraDriver struct {
	base
	api GraphAPI
}

// app is the application as the claim wants it. The claim's one post-logout
// redirect URI is the application's logout URL.
func (d *entraDriver) app(w clientSpec) (idpclient.GraphApp, error) {
	a := idpclient.GraphApp{DisplayName: d.claim.GetExternalName(), Audience: idpclient.GraphAudience, Public: w.public}
	if w.public {
		a.PublicRedirectURIs = w.redirectURIs
	} else {
		a.WebRedirectURIs = w.redirectURIs
	}
	switch len(w.postLogout) {
	case 0:
	case 1:
		a.LogoutURL = w.postLogout[0]
	default:
		return a, ErrEntraLogout
	}
	return a, nil
}

// entraMatches reports whether the application is what the claim wants. The
// redirect URIs of both platforms are exact, so a URI added behind the
// operator's back is drift.
func entraMatches(a, want idpclient.GraphApp, public bool) bool {
	return a.DisplayName == want.DisplayName && a.Audience == want.Audience && a.Public == public &&
		sameSet(a.WebRedirectURIs, want.WebRedirectURIs) && sameSet(a.PublicRedirectURIs, want.PublicRedirectURIs) &&
		a.LogoutURL == want.LogoutURL && (len(a.Passwords) > 0) == !public
}

// observe reads the application by the object ID in status. A claim with no ID
// has made nothing yet.
func (d *entraDriver) observe(ctx context.Context, w clientSpec, wantErr error) (lifecycle.Observation[clientState], error) {
	none := lifecycle.Observation[clientState]{}
	id := d.claim.GetExternalID()
	if id == "" {
		return none, nil
	}
	a, err := d.api.Get(ctx, id)
	if errors.Is(err, idpclient.ErrNotFound) {
		return none, nil
	}
	if err != nil {
		return none, entraErr(err)
	}
	want, appErr := d.app(w)
	return lifecycle.Observation[clientState]{
		Exists:   true,
		UpToDate: wantErr == nil && appErr == nil && entraMatches(a, want, w.public),
		Current:  clientState{ent: entraState{ID: id, AppID: a.AppID, Public: a.Public, HasSecret: len(a.Passwords) > 0}},
	}, nil
}

// passwordName is the display name of the client secret a rotation issues.
func passwordName(sequence int64) string { return fmt.Sprintf("craftainer-%d", sequence) }

func (d *entraDriver) create(ctx context.Context, w clientSpec) (binding.Data, error) {
	a, err := d.app(w)
	if err != nil {
		return nil, err
	}
	made, err := d.api.Create(ctx, a)
	if err != nil {
		if errors.Is(err, idpclient.ErrBadResponse) {
			// The tenant may have made an application the operator cannot name.
			d.orphanRisk(reasonRegistrationUnconfirmed)
		}
		return nil, entraErr(err)
	}
	// Record the application before anything else can fail.
	d.claim.SetExternalID(made.ID)
	if err := d.persist(ctx); err != nil {
		// An application the status does not name would be found by no one at
		// deletion: take it back. One that cannot be is an orphan risk: the claim
		// keeps its id, and the next reconcile manages the application.
		if d.takeBack(ctx, func(c context.Context) error { return d.deleteApp(c, made.ID) }) {
			d.claim.SetExternalID("")
		}
		return nil, err
	}
	if w.public {
		return d.data(made.AppID, ""), nil
	}
	// A failure here leaves an application with no secret: the next reconcile
	// finds it out of date and issues one (update).
	sec, err := d.api.AddPassword(ctx, made.ID, passwordName(0))
	if err != nil {
		return nil, entraErr(err)
	}
	return d.data(made.AppID, sec.Value), nil
}

func (d *entraDriver) update(ctx context.Context, w clientSpec, cur entraState) (binding.Data, error) {
	// An application is not turned from public to confidential or back.
	if cur.Public != w.public && cur.HasSecret == w.public {
		return nil, ErrEntraSecret
	}
	a, err := d.app(w)
	if err != nil {
		return nil, err
	}
	if err := d.api.Update(ctx, cur.ID, a); err != nil {
		return nil, entraErr(err)
	}
	d.claim.SetExternalID(cur.ID)
	if w.public {
		return d.data(cur.AppID, ""), nil
	}
	if !cur.HasSecret {
		// The application was made and its secret never was.
		sec, err := d.api.AddPassword(ctx, cur.ID, passwordName(0))
		if err != nil {
			return nil, entraErr(err)
		}
		return d.data(cur.AppID, sec.Value), nil
	}
	// The secret is not readable again: it is the one the binding Secret holds.
	secret, err := d.currentSecret(ctx)
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, ErrBindingNotUsable
	}
	return d.data(cur.AppID, secret), nil
}

// deleteApp deletes the application; one that is already gone is deleted as far
// as the operator can tell.
func (d *entraDriver) deleteApp(ctx context.Context, id string) error {
	err := d.api.Delete(ctx, id)
	if errors.Is(err, idpclient.ErrNotFound) {
		return nil
	}
	return entraErr(err)
}

// rotateBegin issues a new client secret next to the ones the application has.
// A confidential application can hold several, so the old one stays valid
// through the grace period. The new key ID is the generation. A secret of an
// earlier attempt with the same name (the crash came before the binding was
// written) is removed first, so a retry does not leak one.
func (d *entraDriver) rotateBegin(ctx context.Context, w clientSpec, cur entraState, st lifecycle.RotationState) (binding.Data, lifecycle.Generation, error) {
	if w.public {
		return d.data(cur.AppID, ""), lifecycle.Generation(fmt.Sprint(st.Sequence + 1)), nil
	}
	name := passwordName(st.Sequence + 1)
	a, err := d.api.Get(ctx, cur.ID)
	if err != nil {
		return nil, "", entraErr(err)
	}
	for _, p := range a.Passwords {
		if p.DisplayName == name {
			if err := d.api.RemovePassword(ctx, cur.ID, p.KeyID); err != nil {
				return nil, "", entraErr(err)
			}
		}
	}
	sec, err := d.api.AddPassword(ctx, cur.ID, name)
	if err != nil {
		return nil, "", entraErr(err)
	}
	return d.data(cur.AppID, sec.Value), lifecycle.Generation(sec.KeyID), nil
}

// rotateFinish removes every client secret but the active generation's: the
// first rotation's previous generation (the secret Create issued) is unknown to
// the status, and so is a secret left by a failed attempt.
func (d *entraDriver) rotateFinish(ctx context.Context, w clientSpec, cur entraState, st lifecycle.RotationState) error {
	if w.public || st.Active == "" {
		return nil
	}
	a, err := d.api.Get(ctx, cur.ID)
	if errors.Is(err, idpclient.ErrNotFound) {
		return nil
	}
	if err != nil {
		return entraErr(err)
	}
	// Never remove the active secret, whatever else is wrong.
	if !slices.ContainsFunc(a.Passwords, func(p idpclient.GraphPassword) bool { return strings.EqualFold(p.KeyID, string(st.Active)) }) {
		return ErrBindingNotUsable
	}
	for _, p := range a.Passwords {
		if strings.EqualFold(p.KeyID, string(st.Active)) {
			continue
		}
		if err := d.api.RemovePassword(ctx, cur.ID, p.KeyID); err != nil {
			return entraErr(err)
		}
	}
	return nil
}

// entraExternal is the lifecycle.Rotator of one OidcClient on an Entra
// provider. Every error it returns is coarse.
type entraExternal struct {
	claim             *oidcv1alpha1.OidcClient
	drv               *entraDriver
	name              string
	want              clientSpec
	wantErr           error
	webOriginsDropped bool
}

var _ lifecycle.Rotator[oidcv1alpha1.OidcClientSpec, clientState] = (*entraExternal)(nil)

// entraScopeProblem is ErrEntraScope for a scope that is no OIDC scope, else nil.
func entraScopeProblem(scopes []string) error {
	for _, s := range scopes {
		if !slices.Contains(entraScopes, s) {
			return ErrEntraScope
		}
	}
	return nil
}

// Observe implements lifecycle.External.
func (e *entraExternal) Observe(ctx context.Context, _ oidcv1alpha1.OidcClientSpec) (lifecycle.Observation[clientState], error) {
	e.claim.SetExternalName(e.name)
	setWebOriginsCondition(e.claim, e.webOriginsDropped)
	obs, err := e.drv.observe(ctx, e.want, e.wantErr)
	return obs, coarse(ctx, "observe", err)
}

// Create implements lifecycle.External.
func (e *entraExternal) Create(ctx context.Context, _ oidcv1alpha1.OidcClientSpec) (binding.Data, error) {
	if e.wantErr != nil {
		return nil, coarse(ctx, "create", e.wantErr)
	}
	data, err := e.drv.create(ctx, e.want)
	return data, coarse(ctx, "create", err)
}

// Update implements lifecycle.External.
func (e *entraExternal) Update(ctx context.Context, _ oidcv1alpha1.OidcClientSpec, cur clientState) (binding.Data, error) {
	if e.wantErr != nil {
		return nil, coarse(ctx, "update", e.wantErr)
	}
	data, err := e.drv.update(ctx, e.want, cur.ent)
	return data, coarse(ctx, "update", err)
}

// Delete implements lifecycle.External: the application goes with the claim.
func (e *entraExternal) Delete(ctx context.Context, cur clientState) error {
	return coarse(ctx, "delete", e.drv.deleteApp(ctx, cur.ent.ID))
}

// RotateBegin implements lifecycle.Rotator.
func (e *entraExternal) RotateBegin(ctx context.Context, _ oidcv1alpha1.OidcClientSpec, cur clientState, st lifecycle.RotationState) (binding.Data, lifecycle.Generation, error) {
	if e.wantErr != nil {
		return nil, "", coarse(ctx, "rotate", e.wantErr)
	}
	data, gen, err := e.drv.rotateBegin(ctx, e.want, cur.ent, st)
	return data, gen, coarse(ctx, "rotate", err)
}

// RotateFinish implements lifecycle.Rotator.
func (e *entraExternal) RotateFinish(ctx context.Context, _ oidcv1alpha1.OidcClientSpec, cur clientState, st lifecycle.RotationState) error {
	return coarse(ctx, "rotate", e.drv.rotateFinish(ctx, e.want, cur.ent, st))
}
