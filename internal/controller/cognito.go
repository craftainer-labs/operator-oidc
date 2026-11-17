package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cogtypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// Keys of status.discovered of a Cognito provider.
const (
	discoveredRegion     = "region"
	discoveredResourceID = "resourceId"
	discoveredEndpoint   = "endpoint"
)

// idpCognito is the built-in identity provider every app client supports: the
// user pool itself.
const idpCognito = "COGNITO"

// ErrCognitoSecret means the claim's confidential or public type differs from
// the app client's: an app client cannot gain or lose its secret after it is
// created.
var ErrCognitoSecret = errors.New("a Cognito app client cannot gain or lose its secret: delete the claim and create it again")

// CloudError is a failure to reach or use a cloud API. Its message is a coarse
// category, never SDK text, an ARN or a credential. The probe shows it through
// the library's own reasons (ServerReachable, Ready).
type CloudError struct {
	msg string
	// transient says the failure may pass by itself (the API throttled or
	// timed out).
	transient bool
}

// Error implements error.
func (e *CloudError) Error() string { return e.msg }

// Is makes a transient failure lifecycle.ErrUnreachable, so a claim shows
// ServerReachable=False instead of a generic failure.
func (e *CloudError) Is(target error) bool { return e.transient && target == lifecycle.ErrUnreachable }

func cloudErr(msg string) error { return &CloudError{msg: msg} }

// transientCause says whether err (an HTTP status of 0 means none) is a
// failure that may pass by itself: a deadline, a cancelled context (the manager
// is stopping; says nothing about the cloud), a network error, and an HTTP 408,
// 429 or 5xx answer.
func transientCause(err error, status int) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.As(err, &ne) ||
		status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= http.StatusInternalServerError
}

// cognitoNotFound says err is the API's answer for a user pool or an app
// client that does not exist.
func cognitoNotFound(err error) bool {
	var nf *cogtypes.ResourceNotFoundException
	return errors.As(err, &nf)
}

// cognitoErr classifies a failed Cognito call: an app client that is gone is
// idpclient.ErrNotFound; throttling, timeouts and 5xx-type answers are
// transient (the provider is unreachable for now); anything else (access
// denied, a refused parameter) is a CloudError that is not.
func cognitoErr(err error) error {
	if err == nil {
		return nil
	}
	if cognitoNotFound(err) {
		return fmt.Errorf("%w: the Cognito resource does not exist", idpclient.ErrNotFound)
	}
	// A connection the egress policy or the proxy refused will not pass by
	// itself, whatever net.Error it is wrapped in.
	if errors.Is(err, egress.ErrBlocked) || errors.Is(err, egress.ErrProxy) || errors.Is(err, egress.ErrProxyUserinfo) {
		return cloudErr("the connection to the Cognito API was refused by the egress policy")
	}
	var api interface{ ErrorCode() string }
	var resp interface{ HTTPStatusCode() int }
	status := 0
	if errors.As(err, &resp) {
		status = resp.HTTPStatusCode()
	}
	transient := transientCause(err, status)
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "TooManyRequestsException", "ThrottlingException", "RequestLimitExceeded", "InternalErrorException", "InternalFailure", "ServiceUnavailable", "SlowDown", "RequestTimeout", "RequestTimeoutException":
			transient = true
		}
	}
	if transient {
		return &CloudError{msg: "the Cognito API call failed", transient: true}
	}
	return cloudErr("the Cognito API refused the request")
}

// awsErr is the category of a failure to build the AWS configuration.
func awsErr(err error) error {
	if errors.Is(err, cloud.ErrEndpointOverrideForbidden) || errors.Is(err, cloud.ErrInvalidEndpoint) {
		return cloudErr("endpointOverride is not allowed here")
	}
	return cloudErr("the cloud credentials are unavailable")
}

// CognitoAPI is the part of the Cognito user pools client the operator uses.
type CognitoAPI interface {
	DescribeUserPool(ctx context.Context, in *cip.DescribeUserPoolInput, opts ...func(*cip.Options)) (*cip.DescribeUserPoolOutput, error)
	CreateUserPoolClient(ctx context.Context, in *cip.CreateUserPoolClientInput, opts ...func(*cip.Options)) (*cip.CreateUserPoolClientOutput, error)
	DescribeUserPoolClient(ctx context.Context, in *cip.DescribeUserPoolClientInput, opts ...func(*cip.Options)) (*cip.DescribeUserPoolClientOutput, error)
	UpdateUserPoolClient(ctx context.Context, in *cip.UpdateUserPoolClientInput, opts ...func(*cip.Options)) (*cip.UpdateUserPoolClientOutput, error)
	DeleteUserPoolClient(ctx context.Context, in *cip.DeleteUserPoolClientInput, opts ...func(*cip.Options)) (*cip.DeleteUserPoolClientOutput, error)
}

// NewCognito builds the Cognito client of an aws.Config, whose HTTP client
// dials through the egress policy (cloud.Egress.AWS).
func NewCognito(cfg aws.Config) CognitoAPI { return cip.NewFromConfig(cfg) }

// cognitoClient is a CognitoAPI that can close its idle connections.
type cognitoClient struct {
	CognitoAPI
	hc aws.HTTPClient
}

// CloseIdleConnections releases the connections of the client's HTTP client.
func (c *cognitoClient) CloseIdleConnections() {
	if h, ok := c.hc.(interface{ CloseIdleConnections() }); ok {
		h.CloseIdleConnections()
	}
}

// newCognito builds the client of a Cognito provider with the operator's
// credentials to the cloud (workload identity, or the Secret conn carries).
// Every HTTP connection dials through the egress policy and the provider's
// proxy.
func (c Config) newCognito(ctx context.Context, cg *oidcv1alpha1.CognitoConfig, scope cloud.Scope, creds *cloud.Credentials, conn server.CloudConnection) (*cognitoClient, error) {
	e := cloud.Egress{Mode: c.EgressMode, Policy: c.Egress, Proxy: conn.Proxy}
	cfg, err := e.AWS(ctx, scope, cg.AWSClusterBlock, creds, conn.Credentials)
	if err != nil {
		return nil, awsErr(err)
	}
	factory := c.Cognito
	if factory == nil {
		factory = NewCognito
	}
	return &cognitoClient{CognitoAPI: factory(cfg), hc: cfg.HTTPClient}, nil
}

// cognitoIssuer is the issuer of a user pool's tokens.
func cognitoIssuer(cg *oidcv1alpha1.CognitoConfig) string {
	return "https://cognito-idp." + cg.Region + ".amazonaws.com/" + cg.UserPoolID
}

// cognitoHost is the host of the pool's hosted UI: a domain with a dot is a
// custom domain, one without is the prefix of an Amazon Cognito domain.
func cognitoHost(cg *oidcv1alpha1.CognitoConfig) string {
	if strings.Contains(cg.Domain, ".") {
		return cg.Domain
	}
	return cg.Domain + ".auth." + cg.Region + ".amazoncognito.com"
}

// cognitoDiscovery is the endpoints of a user pool, derived from its
// configuration: the hosted UI serves the authorization, token and user info
// endpoints, and the pool the signing keys.
func cognitoDiscovery(cg *oidcv1alpha1.CognitoConfig) *oidcv1alpha1.Discovery {
	ui := "https://" + cognitoHost(cg) + "/oauth2/"
	return &oidcv1alpha1.Discovery{
		AuthorizationEndpoint: ui + "authorize", TokenEndpoint: ui + "token", UserinfoEndpoint: ui + "userInfo",
		JWKSURI: cognitoIssuer(cg) + "/.well-known/jwks.json",
	}
}

// discoverCognito reads the user pool of a Cognito provider and returns what
// it found for status.discovered. The errors are *CloudError, a category each.
func (c Config) discoverCognito(ctx context.Context, ref providerRef, conn server.CloudConnection) (map[string]string, error) {
	cg := ref.spec.Cognito
	if cg == nil {
		return nil, cloudErr("the provider has no cognito block")
	}
	cl, err := c.newCognito(ctx, cg, ref.scope, ref.creds, conn)
	if err != nil {
		return nil, err
	}
	// The client is built for this call: release its idle connections after it.
	defer cl.CloseIdleConnections()
	out, err := cl.DescribeUserPool(ctx, &cip.DescribeUserPoolInput{UserPoolId: aws.String(cg.UserPoolID)})
	if cognitoNotFound(err) {
		return nil, cloudErr("the user pool does not exist")
	}
	if err != nil {
		return nil, cognitoErr(err)
	}
	if out.UserPool == nil {
		return nil, cloudErr("the Cognito API answered with an unexpected document")
	}
	d := map[string]string{
		discoveredRegion: cg.Region, discoveredResourceID: cg.UserPoolID, discoveredEndpoint: cognitoHost(cg),
	}
	if id := aws.ToString(out.UserPool.Id); id != "" {
		d[discoveredResourceID] = id
	}
	return d, nil
}

// cognitoState is what Observe read of an app client. The secret is the one
// Cognito reports for a confidential client; it is never logged.
type cognitoState struct {
	ID     string
	Secret string
}

// cognitoDriver manages an app client of a user pool. status.externalName is the
// client name and status.externalId the app client ID Cognito assigned: an app
// client has no tag to hold an ownership marker, so it is found by the ID only,
// and a client the status never recorded is not adopted.
type cognitoDriver struct {
	base
	api  CognitoAPI
	pool string
}

// flows are the OAuth flows of the grants. refresh_token is no OAuth flow of
// the app client: it is an explicit auth flow, which every client keeps.
func cognitoFlows(grants []string) []cogtypes.OAuthFlowType {
	var out []cogtypes.OAuthFlowType
	if slices.Contains(grants, string(oidcv1alpha1.GrantAuthorizationCode)) {
		out = append(out, cogtypes.OAuthFlowTypeCode)
	}
	if slices.Contains(grants, string(oidcv1alpha1.GrantClientCredentials)) {
		out = append(out, cogtypes.OAuthFlowTypeClientCredentials)
	}
	return out
}

// refreshOnly is the explicit auth flows of every client: the refresh token
// flow of the OAuth endpoints, and none of the direct sign-in flows (SRP,
// user password, custom), which no OIDC client of this operator needs.
var refreshOnly = []cogtypes.ExplicitAuthFlowsType{cogtypes.ExplicitAuthFlowsTypeAllowRefreshTokenAuth}

func (d *cognitoDriver) createInput(w clientSpec) *cip.CreateUserPoolClientInput {
	flows := cognitoFlows(w.grants)
	return &cip.CreateUserPoolClientInput{
		UserPoolId: aws.String(d.pool), ClientName: aws.String(d.claim.GetExternalName()), GenerateSecret: !w.public,
		CallbackURLs: w.redirectURIs, LogoutURLs: w.postLogout, AllowedOAuthScopes: w.scopes,
		AllowedOAuthFlows: flows, AllowedOAuthFlowsUserPoolClient: len(flows) > 0,
		ExplicitAuthFlows: refreshOnly, SupportedIdentityProviders: []string{idpCognito},
	}
}

// updateInput sends the whole desired state: UpdateUserPoolClient resets what
// it is not given to the defaults.
func (d *cognitoDriver) updateInput(id string, w clientSpec) *cip.UpdateUserPoolClientInput {
	flows := cognitoFlows(w.grants)
	return &cip.UpdateUserPoolClientInput{
		UserPoolId: aws.String(d.pool), ClientId: aws.String(id), ClientName: aws.String(d.claim.GetExternalName()),
		CallbackURLs: w.redirectURIs, LogoutURLs: w.postLogout, AllowedOAuthScopes: w.scopes,
		AllowedOAuthFlows: flows, AllowedOAuthFlowsUserPoolClient: len(flows) > 0,
		ExplicitAuthFlows: refreshOnly, SupportedIdentityProviders: []string{idpCognito},
	}
}

// sameSet reports whether a and b hold the same values, in any order.
func sameSet[T comparable](a, b []T) bool {
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}
	for _, v := range b {
		if !slices.Contains(a, v) {
			return false
		}
	}
	return true
}

// hasSecret says whether the app client was created with a secret.
func hasSecret(c *cogtypes.UserPoolClientType) bool { return aws.ToString(c.ClientSecret) != "" }

// cognitoMatches reports whether the app client is what the claim wants. The
// scopes, flows and URLs are exact, so a scope added behind the operator's back
// is drift.
func cognitoMatches(c *cogtypes.UserPoolClientType, name string, w clientSpec) bool {
	flows := cognitoFlows(w.grants)
	return aws.ToString(c.ClientName) == name &&
		sameSet(c.CallbackURLs, w.redirectURIs) && sameSet(c.LogoutURLs, w.postLogout) &&
		sameSet(c.AllowedOAuthScopes, w.scopes) && sameSet(c.AllowedOAuthFlows, flows) &&
		aws.ToBool(c.AllowedOAuthFlowsUserPoolClient) == (len(flows) > 0) &&
		sameSet(c.ExplicitAuthFlows, refreshOnly) && sameSet(c.SupportedIdentityProviders, []string{idpCognito}) &&
		hasSecret(c) == !w.public
}

// observe reads the app client by the ID in status. A claim with no ID has made
// nothing yet.
func (d *cognitoDriver) observe(ctx context.Context, w clientSpec, wantErr error) (lifecycle.Observation[clientState], error) {
	none := lifecycle.Observation[clientState]{}
	id := d.claim.GetExternalID()
	if id == "" {
		return none, nil
	}
	out, err := d.api.DescribeUserPoolClient(ctx, &cip.DescribeUserPoolClientInput{UserPoolId: aws.String(d.pool), ClientId: aws.String(id)})
	if cognitoNotFound(err) {
		return none, nil
	}
	if err != nil {
		return none, cognitoErr(err)
	}
	c := out.UserPoolClient
	if c == nil {
		return none, idpclient.ErrBadResponse
	}
	return lifecycle.Observation[clientState]{
		Exists:   true,
		UpToDate: wantErr == nil && cognitoMatches(c, d.claim.GetExternalName(), w),
		Current:  clientState{cog: cognitoState{ID: id, Secret: aws.ToString(c.ClientSecret)}},
	}, nil
}

// bindingData is the binding of the client with its secret (none for a public
// client, which has none).
func (d *cognitoDriver) bindingData(w clientSpec, id, secret string) (binding.Data, error) {
	if w.public {
		return d.data(id, ""), nil
	}
	if secret == "" {
		return nil, idpclient.ErrBadResponse
	}
	return d.data(id, secret), nil
}

func (d *cognitoDriver) create(ctx context.Context, w clientSpec) (binding.Data, error) {
	out, err := d.api.CreateUserPoolClient(ctx, d.createInput(w))
	if err != nil {
		return nil, cognitoErr(err)
	}
	if out.UserPoolClient == nil || aws.ToString(out.UserPoolClient.ClientId) == "" {
		// The pool may have made a client the operator cannot name.
		d.orphanRisk(reasonRegistrationUnconfirmed)
		return nil, idpclient.ErrBadResponse
	}
	c := out.UserPoolClient
	id := aws.ToString(c.ClientId)
	// Record the client before anything else can fail.
	d.claim.SetExternalID(id)
	if err := d.persist(ctx); err != nil {
		// A client the status does not name would be found by no one at deletion:
		// take it back. One that cannot be is an orphan risk: the claim keeps its
		// id, and the next reconcile manages the client.
		if d.takeBack(ctx, func(c2 context.Context) error { return d.deleteClient(c2, id) }) {
			d.claim.SetExternalID("")
		}
		return nil, err
	}
	return d.bindingData(w, id, aws.ToString(c.ClientSecret))
}

func (d *cognitoDriver) update(ctx context.Context, w clientSpec, cur cognitoState) (binding.Data, error) {
	// A client cannot gain or lose its secret, so a changed type is not fixable
	// by an update.
	if (cur.Secret != "") == w.public {
		return nil, ErrCognitoSecret
	}
	if _, err := d.api.UpdateUserPoolClient(ctx, d.updateInput(cur.ID, w)); err != nil {
		return nil, cognitoErr(err)
	}
	d.claim.SetExternalID(cur.ID)
	return d.bindingData(w, cur.ID, cur.Secret)
}

func (d *cognitoDriver) deleteClient(ctx context.Context, id string) error {
	_, err := d.api.DeleteUserPoolClient(ctx, &cip.DeleteUserPoolClientInput{UserPoolId: aws.String(d.pool), ClientId: aws.String(id)})
	// An app client that is already gone is deleted as far as the operator can
	// tell.
	if cognitoNotFound(err) {
		return nil
	}
	return cognitoErr(err)
}

// cognitoExternal is the lifecycle.External of one OidcClient on a Cognito
// provider. An app client's secret cannot be rotated in place, so it is a
// lifecycle.NonRotator (the rotate annotation is acknowledged and ignored, and
// a rotationPolicy does nothing). The binding holds nothing the pool does not
// report again (the secret is readable with DescribeUserPoolClient), so a
// missing binding Secret is rebuilt, not reissued. Every error it returns is
// coarse.
type cognitoExternal struct {
	claim             *oidcv1alpha1.OidcClient
	drv               *cognitoDriver
	name              string
	want              clientSpec
	wantErr           error
	webOriginsDropped bool
}

var (
	_ lifecycle.External[oidcv1alpha1.OidcClientSpec, clientState]         = (*cognitoExternal)(nil)
	_ lifecycle.NonRotator                                                 = (*cognitoExternal)(nil)
	_ lifecycle.BindingRebuilder[oidcv1alpha1.OidcClientSpec, clientState] = (*cognitoExternal)(nil)
)

// Observe implements lifecycle.External.
func (e *cognitoExternal) Observe(ctx context.Context, _ oidcv1alpha1.OidcClientSpec) (lifecycle.Observation[clientState], error) {
	e.claim.SetExternalName(e.name)
	setWebOriginsCondition(e.claim, e.webOriginsDropped)
	obs, err := e.drv.observe(ctx, e.want, e.wantErr)
	return obs, coarse(ctx, "observe", err)
}

// Create implements lifecycle.External.
func (e *cognitoExternal) Create(ctx context.Context, _ oidcv1alpha1.OidcClientSpec) (binding.Data, error) {
	if e.wantErr != nil {
		return nil, coarse(ctx, "create", e.wantErr)
	}
	data, err := e.drv.create(ctx, e.want)
	return data, coarse(ctx, "create", err)
}

// Update implements lifecycle.External.
func (e *cognitoExternal) Update(ctx context.Context, _ oidcv1alpha1.OidcClientSpec, cur clientState) (binding.Data, error) {
	if e.wantErr != nil {
		return nil, coarse(ctx, "update", e.wantErr)
	}
	data, err := e.drv.update(ctx, e.want, cur.cog)
	return data, coarse(ctx, "update", err)
}

// Delete implements lifecycle.External: the app client goes with the claim.
func (e *cognitoExternal) Delete(ctx context.Context, cur clientState) error {
	return coarse(ctx, "delete", e.drv.deleteClient(ctx, cur.cog.ID))
}

// RotationNotApplicable implements lifecycle.NonRotator.
func (*cognitoExternal) RotationNotApplicable() bool { return true }

// RebuildBinding implements lifecycle.BindingRebuilder: the binding Secret is
// written again from the app client Observe read.
func (e *cognitoExternal) RebuildBinding(ctx context.Context, _ oidcv1alpha1.OidcClientSpec, cur clientState) (binding.Data, error) {
	data, err := e.drv.bindingData(e.want, cur.cog.ID, cur.cog.Secret)
	return data, coarse(ctx, "rebuild the binding", err)
}
