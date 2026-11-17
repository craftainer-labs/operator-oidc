package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
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

// textEntraEndpoint is the text of a Graph base that is no https URL, or has a
// query or a fragment (the egress policy's own refusals say "not allowed here").
const textEntraEndpoint = "endpointOverride must be an https URL with no credentials, query or fragment"

// entraScopes are the scopes an Entra application grants without an API
// permission: the OIDC scopes of the Microsoft identity platform.
var entraScopes = []string{"openid", "profile", "email", "offline_access"}

// GraphAPI is the part of the Microsoft Graph client the operator uses
// (*idpclient.Graph).
type GraphAPI interface {
	Probe(ctx context.Context) error
	Get(ctx context.Context, id string) (idpclient.GraphApp, error)
	GetByUniqueName(ctx context.Context, name string) (idpclient.GraphApp, error)
	// Create is idempotent on a.UniqueName: it returns the application an
	// earlier call made.
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
	cred := az.Credential
	if cred == nil {
		return nil, cloudErr("the cloud credentials are unavailable")
	}
	// The credential is asked directly, not through cloud.AzureTokenSource,
	// which drops the cause: entraErr needs it to tell a refusal from a timeout.
	// The credential caches tokens itself.
	g, err := idpclient.NewGraph(hc, base, func(ctx context.Context) (string, error) {
		tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{idpclient.GraphScope}})
		return tok.Token, err
	})
	if err != nil {
		return nil, cloudErr(textEntraEndpoint)
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
		return tokenErr(err)
	}
	var se *idpclient.Error
	if errors.As(err, &se) && transientCause(nil, se.Status) {
		return &CloudError{msg: "the Graph API call failed", transient: true}
	}
	return err
}

// tokenErr classifies a token fetch that failed. A connection the egress policy
// refused stays a refusal; a deadline, a network error and a 408, 429 or 5xx
// answer of the authority pass by themselves (the provider is unreachable for
// now); a refusal of the credentials (a 4xx answer, a missing credential) does
// not. It never carries the cause's text.
func tokenErr(err error) error {
	if errors.Is(err, egress.ErrBlocked) || errors.Is(err, egress.ErrProxy) || errors.Is(err, egress.ErrProxyUserinfo) {
		return cloudErr("the connection to the Entra authority was refused by the egress policy")
	}
	status := 0
	var af *azidentity.AuthenticationFailedError
	if errors.As(err, &af) && af.RawResponse != nil {
		status = af.RawResponse.StatusCode
	}
	if transientCause(err, status) {
		return &CloudError{msg: "the Entra authority call failed", transient: true}
	}
	return cloudErr("the cloud credentials are unavailable")
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
// Graph assigned. An application carries no ownership marker the operator may
// rely on (ADR 0004), so it is found by the object ID, and an application the
// status never recorded is not adopted. The one exception is the claim's own
// uniqueName: creating is an upsert on it, and a read by it stands in for a
// 404 by object ID (Graph is eventually consistent), so a retry never makes a
// second application. The operator can see and change only the applications its
// identity owns (Application.ReadWrite.OwnedBy), so a name it finds is its own.
type entraDriver struct {
	base
	api GraphAPI
}

// app is the application as the claim wants it. The claim's one post-logout
// redirect URI is the application's logout URL.
func (d *entraDriver) app(w clientSpec) (idpclient.GraphApp, error) {
	a := idpclient.GraphApp{
		UniqueName:  idpclient.EntraUniqueName(d.claim.Namespace, d.claim.Name),
		DisplayName: d.claim.GetExternalName(), Audience: idpclient.GraphAudience, Public: w.public,
	}
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
		// Graph is eventually consistent: an application made a moment ago may
		// not be readable by its object ID yet. Its uniqueName says whether it
		// is there, so a lagging read does not make a second one.
		a, err = d.api.GetByUniqueName(ctx, idpclient.EntraUniqueName(d.claim.Namespace, d.claim.Name))
		if errors.Is(err, idpclient.ErrNotFound) {
			return none, nil
		}
		if err == nil && a.ID != id {
			id = a.ID
			d.claim.SetExternalID(id)
		}
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

// create makes the application, or finds the one an earlier attempt made (the
// create is an upsert on the claim's uniqueName), so a status that could not be
// written, or an answer that was lost, leaves nothing behind: the next attempt
// is the same application.
func (d *entraDriver) create(ctx context.Context, w clientSpec) (binding.Data, error) {
	a, err := d.app(w)
	if err != nil {
		return nil, err
	}
	made, err := d.api.Create(ctx, a)
	if err != nil {
		return nil, entraErr(err)
	}
	// Record the application before anything else can fail.
	d.claim.SetExternalID(made.ID)
	if err := d.persist(ctx); err != nil {
		return nil, err
	}
	if w.public {
		return d.data(made.AppID, ""), nil
	}
	// A failure here leaves an application with no secret the binding holds: the
	// next reconcile finds the application out of date and goes through the same
	// path (update).
	return d.secretData(ctx, made.ID, made.AppID, made.Passwords)
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
	have, err := d.api.Get(ctx, cur.ID)
	if err != nil {
		return nil, entraErr(err)
	}
	return d.secretData(ctx, cur.ID, cur.AppID, have.Passwords)
}

// heldBy says the secret is one of the application's: Graph keeps the first
// three characters of a secret (its hint) readable, which is all the operator
// can compare a secret it cannot read again with.
func heldBy(have []idpclient.GraphPassword, secret string) bool {
	return len(secret) >= 3 && slices.ContainsFunc(have, func(p idpclient.GraphPassword) bool { return p.Hint == secret[:3] })
}

// secretData is the binding data of a confidential application: the secret the
// binding Secret holds when the application still has it, else a new one. A
// secret is not readable again, so a binding that is missing, empty or names a
// secret the application no longer has is not an error: it gets a new secret.
func (d *entraDriver) secretData(ctx context.Context, id, appID string, have []idpclient.GraphPassword) (binding.Data, error) {
	bound, err := d.currentSecret(ctx)
	if err != nil {
		return nil, err
	}
	if heldBy(have, bound) {
		return d.data(appID, bound), nil
	}
	sec, err := d.issue(ctx, id, passwordName(0), bound)
	if err != nil {
		return nil, err
	}
	return d.data(appID, sec.Value), nil
}

// issue adds a client secret named name. It then removes the secrets of the
// same name an earlier attempt left (the add succeeded and the binding was never
// written), so the count stays bounded, except the one the binding Secret still
// holds (bound): the binding stays valid until it is written again, and
// RotateFinish removes that one later. The new secret is written to Graph first
// and nothing is removed before it. The clean-up is best effort: a failure
// there loses nothing, the next attempt or RotateFinish does it.
func (d *entraDriver) issue(ctx context.Context, id, name, bound string) (idpclient.GraphSecret, error) {
	sec, err := d.api.AddPassword(ctx, id, name)
	if err != nil {
		return sec, entraErr(err)
	}
	app, err := d.api.Get(ctx, id)
	if err != nil {
		return sec, nil
	}
	for _, p := range app.Passwords {
		if p.DisplayName != name || strings.EqualFold(p.KeyID, sec.KeyID) || heldBy([]idpclient.GraphPassword{p}, bound) {
			continue
		}
		if err := d.api.RemovePassword(ctx, id, p.KeyID); err != nil {
			break
		}
	}
	return sec, nil
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
// through the grace period. The new key ID is the generation. The secret is
// added first; a secret of an earlier attempt with the same name is removed
// afterwards unless the binding Secret holds it (see issue), and RotateFinish
// removes every secret but the active one.
func (d *entraDriver) rotateBegin(ctx context.Context, w clientSpec, cur entraState, st lifecycle.RotationState) (binding.Data, lifecycle.Generation, error) {
	if w.public {
		return d.data(cur.AppID, ""), lifecycle.Generation(fmt.Sprint(st.Sequence + 1)), nil
	}
	bound, err := d.currentSecret(ctx)
	if err != nil {
		return nil, "", err
	}
	sec, err := d.issue(ctx, cur.ID, passwordName(st.Sequence+1), bound)
	if err != nil {
		return nil, "", err
	}
	return d.data(cur.AppID, sec.Value), lifecycle.Generation(sec.KeyID), nil
}

// rotateFinish removes every client secret but the active generation's and the
// one the binding Secret holds: the first rotation's previous generation (the
// secret Create issued) is unknown to the status, and so is a secret left by a
// failed attempt.
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
	// The binding Secret may hold a secret that is not the active generation (one
	// issued for a binding that had none, while a rotation was open): it is
	// kept, or the binding would name a secret that is gone.
	bound, err := d.currentSecret(ctx)
	if err != nil {
		return err
	}
	// Never remove the active secret, whatever else is wrong.
	if !slices.ContainsFunc(a.Passwords, func(p idpclient.GraphPassword) bool { return strings.EqualFold(p.KeyID, string(st.Active)) }) {
		return ErrBindingNotUsable
	}
	for _, p := range a.Passwords {
		if strings.EqualFold(p.KeyID, string(st.Active)) || heldBy([]idpclient.GraphPassword{p}, bound) {
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
