package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cogtypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

const (
	testPool    = "eu-west-1_AbCdEf123"
	testPoolARN = "arn:aws:cognito-idp:eu-west-1:111122223333:userpool/" + testPool
)

// apiErr is an error of the Cognito API as the SDK shapes it, with text that
// must never reach a condition.
type apiErr struct {
	code   string
	status int
}

func (e *apiErr) Error() string       { return e.code + ": AKIASECRET denied for arn:aws:iam::1:role/x" }
func (e *apiErr) ErrorCode() string   { return e.code }
func (e *apiErr) HTTPStatusCode() int { return e.status }

var (
	errRefused   = &apiErr{code: "InvalidParameterException", status: 400}
	errThrottled = &apiErr{code: "TooManyRequestsException", status: 400}
	errNotFound  = &cogtypes.ResourceNotFoundException{Message: aws.String("AKIASECRET")}
)

// fakeCognito is the part of the Cognito API the operator uses, over one user
// pool: the app clients are what the calls made them.
type fakeCognito struct {
	mu      sync.Mutex
	pool    *cogtypes.UserPoolType
	poolID  string
	clients map[string]*cogtypes.UserPoolClientType
	n       int
	inputs  []*cip.CreateUserPoolClientInput
	calls   []string
	// failOp maps "create", "describe", "update", "delete" and "pool" to the
	// error the fake answers.
	failOp map[string]error
	// createEmpty makes a create answer without a client ID; createNoSecret
	// without a secret; describeEmpty makes a describe answer without a client;
	// poolEmpty makes DescribeUserPool answer without a pool.
	createEmpty, createNoSecret, describeEmpty, poolEmpty bool
}

func newFakeCognito() *fakeCognito {
	return &fakeCognito{
		pool: &cogtypes.UserPoolType{Id: aws.String(testPool), Arn: aws.String(testPoolARN)}, poolID: testPool,
		clients: map[string]*cogtypes.UserPoolClientType{}, failOp: map[string]error{},
	}
}

func (f *fakeCognito) enter(op string) error {
	f.calls = append(f.calls, op)
	return f.failOp[op]
}

func (f *fakeCognito) count(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == op {
			n++
		}
	}
	return n
}

func (f *fakeCognito) with(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeCognito) DescribeUserPool(_ context.Context, in *cip.DescribeUserPoolInput, _ ...func(*cip.Options)) (*cip.DescribeUserPoolOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("pool"); err != nil {
		return nil, err
	}
	if f.poolEmpty {
		return &cip.DescribeUserPoolOutput{}, nil
	}
	if aws.ToString(in.UserPoolId) != f.poolID {
		return nil, errNotFound
	}
	return &cip.DescribeUserPoolOutput{UserPool: f.pool}, nil
}

func (f *fakeCognito) CreateUserPoolClient(_ context.Context, in *cip.CreateUserPoolClientInput, _ ...func(*cip.Options)) (*cip.CreateUserPoolClientOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("create"); err != nil {
		return nil, err
	}
	f.inputs = append(f.inputs, in)
	if f.createEmpty {
		return &cip.CreateUserPoolClientOutput{}, nil
	}
	f.n++
	id := fmt.Sprintf("client%d", f.n)
	c := &cogtypes.UserPoolClientType{
		ClientId: aws.String(id), ClientName: in.ClientName, CallbackURLs: in.CallbackURLs, LogoutURLs: in.LogoutURLs,
		AllowedOAuthFlows: in.AllowedOAuthFlows, AllowedOAuthFlowsUserPoolClient: aws.Bool(in.AllowedOAuthFlowsUserPoolClient),
		AllowedOAuthScopes: in.AllowedOAuthScopes, ExplicitAuthFlows: in.ExplicitAuthFlows,
		SupportedIdentityProviders: in.SupportedIdentityProviders,
	}
	if in.GenerateSecret && !f.createNoSecret {
		c.ClientSecret = aws.String("secret-" + id)
	}
	f.clients[id] = c
	out := *c
	return &cip.CreateUserPoolClientOutput{UserPoolClient: &out}, nil
}

func (f *fakeCognito) DescribeUserPoolClient(_ context.Context, in *cip.DescribeUserPoolClientInput, _ ...func(*cip.Options)) (*cip.DescribeUserPoolClientOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("describe"); err != nil {
		return nil, err
	}
	if f.describeEmpty {
		return &cip.DescribeUserPoolClientOutput{}, nil
	}
	c, ok := f.clients[aws.ToString(in.ClientId)]
	if !ok {
		return nil, errNotFound
	}
	out := *c
	return &cip.DescribeUserPoolClientOutput{UserPoolClient: &out}, nil
}

func (f *fakeCognito) UpdateUserPoolClient(_ context.Context, in *cip.UpdateUserPoolClientInput, _ ...func(*cip.Options)) (*cip.UpdateUserPoolClientOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("update"); err != nil {
		return nil, err
	}
	c, ok := f.clients[aws.ToString(in.ClientId)]
	if !ok {
		return nil, errNotFound
	}
	c.ClientName, c.CallbackURLs, c.LogoutURLs = in.ClientName, in.CallbackURLs, in.LogoutURLs
	c.AllowedOAuthFlows, c.AllowedOAuthFlowsUserPoolClient = in.AllowedOAuthFlows, aws.Bool(in.AllowedOAuthFlowsUserPoolClient)
	c.AllowedOAuthScopes, c.ExplicitAuthFlows, c.SupportedIdentityProviders = in.AllowedOAuthScopes, in.ExplicitAuthFlows, in.SupportedIdentityProviders
	return &cip.UpdateUserPoolClientOutput{}, nil
}

func (f *fakeCognito) DeleteUserPoolClient(_ context.Context, in *cip.DeleteUserPoolClientInput, _ ...func(*cip.Options)) (*cip.DeleteUserPoolClientOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("delete"); err != nil {
		return nil, err
	}
	if _, ok := f.clients[aws.ToString(in.ClientId)]; !ok {
		return nil, errNotFound
	}
	delete(f.clients, aws.ToString(in.ClientId))
	return &cip.DeleteUserPoolClientOutput{}, nil
}

// fakeFactory is Config.Cognito for a test: every client is f.
func fakeFactory(f *fakeCognito) func(aws.Config) CognitoAPI {
	return func(aws.Config) CognitoAPI { return f }
}

// cognitoProvider is a cluster provider of type Cognito that every namespace
// may use, with static credentials in the operator namespace.
func cognitoProvider() *oidcv1alpha1.ClusterIdentityProvider {
	p := &oidcv1alpha1.ClusterIdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "cog", UID: "uid-cog", Generation: 1}}
	p.Spec.ProviderConfig = oidcv1alpha1.ProviderConfig{
		Type: oidcv1alpha1.ProviderCognito, AllowedScopes: allowedScopes,
		Cognito: &oidcv1alpha1.CognitoConfig{
			AWSClusterBlock: cloud.AWSClusterBlock{AWSBlock: cloud.AWSBlock{Region: "eu-west-1"}},
			UserPoolID:      testPool, Domain: "team-auth",
		},
	}
	p.Spec.Credentials = &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "aws", Namespace: opsNS}}
	p.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesAll}
	return p
}

var awsKeys = map[string]string{"accessKeyId": "AKIATEST", "secretAccessKey": "not-a-secret"}

// cognitoObjects are a namespace, the credentials Secret and the provider.
func cognitoObjects() []client.Object {
	return []client.Object{namespace("team"), secret(opsNS, "aws", awsKeys), cognitoProvider()}
}

// cognitoClaim is a client of the provider "cog".
func cognitoClaim(mut ...func(*oidcv1alpha1.OidcClient)) *oidcv1alpha1.OidcClient {
	return oidcClient(append([]func(*oidcv1alpha1.OidcClient){
		func(c *oidcv1alpha1.OidcClient) { c.Spec.ServerRef = ref(kindClusterIdentityProvider, "cog") },
	}, mut...)...)
}

func newCognitoOC(t *testing.T, f *fakeCognito, funcs interceptor.Funcs, mut ...func(*oidcv1alpha1.OidcClient)) *oc {
	t.Helper()
	o := newOC(t, funcs, with(cognitoObjects(), cognitoClaim(mut...))...)
	o.r.Cognito = fakeFactory(f)
	return o
}

// failing reconciles and expects an error shown as the fixed text.
func (o *oc) failing(text string) *metav1.Condition {
	o.t.Helper()
	if _, err := o.reconcile(); err == nil {
		o.t.Fatal("a failure was not reported")
	}
	c := wantCond(o.t, o.get(), conditions.Synced, metav1.ConditionFalse, "")
	if !strings.Contains(c.Message, text) || strings.Contains(c.Message, "AKIA") || strings.Contains(c.Message, "arn:") {
		o.t.Errorf("message = %q, want %q", c.Message, text)
	}
	return c
}

// An app client is made with exactly the claim's settings, left alone while it
// matches, corrected when it drifts and deleted with the claim; the binding
// Secret holds the issuer, the endpoints and the client ID and secret.
func TestCognitoClientLifecycle(t *testing.T) {
	f := newFakeCognito()
	o := newCognitoOC(t, f, interceptor.Funcs{})

	o.ok()
	c := o.get()
	wantCond(t, c, conditions.Ready, metav1.ConditionTrue, "")
	name := idpclient.CognitoClientName("team", "web")
	if c.Status.ExternalID != "client1" || c.Status.ExternalName != name {
		t.Fatalf("status = %q %q", c.Status.ExternalID, c.Status.ExternalName)
	}
	in := f.inputs[0]
	if aws.ToString(in.UserPoolId) != testPool || aws.ToString(in.ClientName) != name || !in.GenerateSecret ||
		!slices.Equal(in.CallbackURLs, []string{"https://app.example/cb"}) || !slices.Equal(in.AllowedOAuthScopes, []string{"openid", "profile"}) ||
		!slices.Equal(in.AllowedOAuthFlows, []cogtypes.OAuthFlowType{cogtypes.OAuthFlowTypeCode}) || !in.AllowedOAuthFlowsUserPoolClient ||
		!slices.Equal(in.ExplicitAuthFlows, refreshOnly) || !slices.Equal(in.SupportedIdentityProviders, []string{"COGNITO"}) {
		t.Errorf("create input = %+v", in)
	}
	s := o.secret("team", "web")
	want := map[string]string{
		"clientId": "client1", "clientSecret": "secret-client1",
		"issuer":                "https://cognito-idp.eu-west-1.amazonaws.com/" + testPool,
		"authorizationEndpoint": "https://team-auth.auth.eu-west-1.amazoncognito.com/oauth2/authorize",
		"tokenEndpoint":         "https://team-auth.auth.eu-west-1.amazoncognito.com/oauth2/token",
		"userinfoEndpoint":      "https://team-auth.auth.eu-west-1.amazoncognito.com/oauth2/userInfo",
		"jwksUri":               "https://cognito-idp.eu-west-1.amazonaws.com/" + testPool + "/.well-known/jwks.json",
	}
	for k, v := range want {
		if s == nil || string(s.Data[k]) != v {
			t.Errorf("binding %s = %q, want %q", k, s.Data[k], v)
		}
	}

	// A matching client is not written again.
	o.ok()
	if f.count("update") != 0 {
		t.Fatal("a matching client was updated")
	}

	// Drift in the redirect URIs and in the scopes is corrected, once each, and
	// the secret is kept.
	f.with(func() { f.clients["client1"].CallbackURLs = []string{"https://evil.example/cb"} })
	o.ok()
	f.with(func() {
		f.clients["client1"].AllowedOAuthScopes = append(f.clients["client1"].AllowedOAuthScopes, "email")
	})
	o.ok()
	f.with(func() {
		got := f.clients["client1"]
		if f.n != 1 || !slices.Equal(got.CallbackURLs, []string{"https://app.example/cb"}) ||
			!slices.Equal(got.AllowedOAuthScopes, []string{"openid", "profile"}) {
			t.Errorf("client after drift = %+v", got)
		}
	})
	if n := f.count("update"); n != 2 {
		t.Errorf("updates = %d", n)
	}
	if got := string(o.secret("team", "web").Data["clientSecret"]); got != "secret-client1" {
		t.Errorf("secret after updates = %q", got)
	}

	// Deleting the claim deletes the app client.
	o.del()
	o.ok()
	if !o.gone() || len(f.clients) != 0 {
		t.Errorf("claim gone = %v, clients = %d", o.gone(), len(f.clients))
	}
}

// An app client's secret cannot be rotated in place: the rotate annotation is
// acknowledged and ignored with a Warning Event, the claim stays Synced, and a
// binding Secret that was deleted is written again from what the pool reports,
// with no new client.
func TestCognitoRotationIsNotApplicableAndBindingIsRebuilt(t *testing.T) {
	f := newFakeCognito()
	o := newCognitoOC(t, f, interceptor.Funcs{})
	o.ok()

	o.rotate("1")
	o.ok()
	c := o.get()
	if !o.rec.has("Warning "+conditions.EventRotationNotApplicable) || c.Status.Rotation == nil || c.Status.Rotation.LastTrigger != "1" {
		t.Errorf("events = %v, rotation = %+v", o.rec.events, c.Status.Rotation)
	}
	wantCond(t, c, conditions.Synced, metav1.ConditionTrue, "")
	if got := string(o.secret("team", "web").Data["clientSecret"]); got != "secret-client1" || f.n != 1 {
		t.Errorf("secret = %q after %d clients", got, f.n)
	}

	if err := o.c.Delete(context.Background(), o.secret("team", "web")); err != nil {
		t.Fatal(err)
	}
	o.ok()
	if got := o.secret("team", "web"); got == nil || string(got.Data["clientSecret"]) != "secret-client1" || f.n != 1 {
		t.Errorf("rebuilt binding = %v after %d clients", got, f.n)
	}
	if !o.rec.has("Normal " + conditions.EventBindingRepaired) {
		t.Errorf("events = %v", o.rec.events)
	}
}

// A public client has no secret, a client_credentials client has no redirect
// URI and no code flow, and web origins, which an app client has no field
// for, are reported and dropped.
func TestCognitoPublicAndClientCredentialsClients(t *testing.T) {
	f := newFakeCognito()
	o := newCognitoOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = true })
	o.ok()
	if s := o.secret("team", "web"); f.inputs[0].GenerateSecret || s == nil || s.Data["clientSecret"] != nil || string(s.Data["clientId"]) != "client1" {
		t.Errorf("public client: %+v, %v", f.inputs[0], s)
	}
	f.with(func() { f.inputs = nil })
	o.ok()
	if f.count("update") != 0 {
		t.Error("a matching public client was updated")
	}

	f = newFakeCognito()
	o = newCognitoOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) {
		c.Spec.GrantTypes = []oidcv1alpha1.GrantType{oidcv1alpha1.GrantClientCredentials, oidcv1alpha1.GrantRefreshToken}
		c.Spec.RedirectURIs = nil
		c.Spec.WebOrigins = []oidcv1alpha1.WebOrigin{"https://app.example"}
	})
	o.ok()
	in := f.inputs[0]
	if !slices.Equal(in.AllowedOAuthFlows, []cogtypes.OAuthFlowType{cogtypes.OAuthFlowTypeClientCredentials}) || !in.AllowedOAuthFlowsUserPoolClient || len(in.CallbackURLs) != 0 {
		t.Errorf("create input = %+v", in)
	}
	got := wantCond(t, o.get(), conditionWebOriginsIgnored, metav1.ConditionTrue, reasonWebOriginsIgnored)
	if got.Message != textWebOriginsIgnored {
		t.Errorf("message = %q", got.Message)
	}
}

// An app client cannot gain or lose its secret, so a claim that changes its
// type is refused with a fixed text and nothing is changed.
func TestCognitoClientTypeCannotChange(t *testing.T) {
	f := newFakeCognito()
	o := newCognitoOC(t, f, interceptor.Funcs{})
	o.ok()
	o.edit(func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = true })
	o.failing(ErrCognitoSecret.Error())
	if f.count("update") != 0 {
		t.Error("an app client was updated into another type")
	}
	// The other way round: a public client that wants a secret.
	f = newFakeCognito()
	o = newCognitoOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = true })
	o.ok()
	o.edit(func(c *oidcv1alpha1.OidcClient) { c.Spec.Public = false })
	o.failing(ErrCognitoSecret.Error())
}

// A spec the CRD and the webhook would have refused is refused again before
// anything is made, and the claim can still be deleted.
func TestCognitoInvalidSpecIsRefusedAgain(t *testing.T) {
	f := newFakeCognito()
	o := newCognitoOC(t, f, interceptor.Funcs{}, func(c *oidcv1alpha1.OidcClient) { c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "admin"} })
	o.failing("is not in the provider's allowedScopes")
	if f.count("create") != 0 {
		t.Error("an app client was made")
	}

	f = newFakeCognito()
	o = newCognitoOC(t, f, interceptor.Funcs{})
	o.ok()
	o.edit(func(c *oidcv1alpha1.OidcClient) { c.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "admin"} })
	o.failing("is not in the provider's allowedScopes")
	if f.count("update") != 0 {
		t.Error("an invalid spec was sent to the pool")
	}
	o.del()
	o.ok()
	if !o.gone() {
		t.Error("the claim was not deleted")
	}
}

// A failing API shows one fixed text per kind of failure, never its own words,
// and a throttled or timed out call says the provider is unreachable.
func TestCognitoAPIFailuresAreCategories(t *testing.T) {
	f := newFakeCognito()
	f.failOp["create"] = errRefused
	o := newCognitoOC(t, f, interceptor.Funcs{})
	o.failing("the Cognito API refused the request")

	f.failOp["create"] = errThrottled
	o.failing("the Cognito API call failed")
	wantCond(t, o.get(), conditions.ServerReachable, metav1.ConditionFalse, conditions.ServerUnreachable)

	// A create answered without a client ID may have made one: say so.
	f.failOp["create"] = nil
	f.createEmpty = true
	o.failing("the provider answered with an unexpected document")
	wantCond(t, o.get(), conditionRegistrationUnconfirmed, metav1.ConditionTrue, reasonRegistrationUnconfirmed)

	// A confidential client the pool made without a secret has no binding.
	f.createEmpty, f.createNoSecret = false, true
	o.failing("the provider answered with an unexpected document")
	if o.secret("team", "web") != nil {
		t.Error("a binding Secret was written without a secret")
	}
}

// Observe tells a client someone deleted from one that cannot be read.
func TestCognitoObserveFailures(t *testing.T) {
	f := newFakeCognito()
	o := newCognitoOC(t, f, interceptor.Funcs{})
	o.ok()
	f.with(func() { delete(f.clients, "client1") })
	o.ok()
	if c := o.get(); c.Status.ExternalID != "client2" {
		t.Errorf("externalId = %q", c.Status.ExternalID)
	}
	f.failOp["describe"] = errRefused
	o.failing("the Cognito API refused the request")
	f.failOp["describe"] = nil
	f.describeEmpty = true
	o.failing("the provider answered with an unexpected document")
}

// An update the pool refuses, an app client that vanished meanwhile and a
// delete that fails are reported; a delete of a client that is already gone
// succeeds.
func TestCognitoUpdateAndDeleteFailures(t *testing.T) {
	f := newFakeCognito()
	o := newCognitoOC(t, f, interceptor.Funcs{})
	o.ok()
	f.with(func() { f.clients["client1"].CallbackURLs = []string{"https://evil.example/cb"} })
	f.failOp["update"] = errNotFound
	o.failing("the operation failed")
	f.failOp["update"] = errRefused
	o.failing("the Cognito API refused the request")
	f.failOp["update"] = nil

	o.del()
	f.failOp["delete"] = errRefused
	if _, err := o.reconcile(); err == nil || o.gone() {
		t.Fatalf("a failed delete released the claim: %v", err)
	}
	f.failOp["delete"] = errNotFound
	o.ok()
	if !o.gone() {
		t.Error("an app client that is already gone held the claim")
	}
}

// An app client the status cannot record is taken back at once, and one that
// cannot be taken back is reported.
func TestCognitoCreateTakesBackWhatItCannotRecord(t *testing.T) {
	failStatus := interceptor.Funcs{SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
		return errors.New("the API server is down")
	}}
	f := newFakeCognito()
	o := newCognitoOC(t, f, failStatus)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a status that could not be written was not reported")
	}
	if len(f.clients) != 0 || f.count("delete") != 1 {
		t.Errorf("the app client was not taken back: %d clients, %d deletes", len(f.clients), f.count("delete"))
	}

	f = newFakeCognito()
	f.failOp["delete"] = errRefused
	o = newCognitoOC(t, f, failStatus)
	if _, err := o.reconcile(); err == nil {
		t.Fatal("a status that could not be written was not reported")
	}
	if len(f.clients) != 1 || !o.rec.has("Warning "+reasonCleanupFailed) {
		t.Errorf("%d clients, events = %v", len(f.clients), o.rec.events)
	}
}

// A provider whose credentials cannot be used is refused with a fixed text.
func TestCognitoCredentialProblems(t *testing.T) {
	// The credentials Secret is missing, or in a namespace the provider may not use.
	o := newOC(t, interceptor.Funcs{}, namespace("team"), cognitoProvider(), cognitoClaim())
	o.failing(invalidProvider)
	elsewhere := cognitoProvider()
	elsewhere.Spec.Credentials.SecretRef.Namespace = "team"
	o = newOC(t, interceptor.Funcs{}, namespace("team"), secret("team", "aws", awsKeys), elsewhere, cognitoClaim())
	o.failing(invalidProvider)

	// A Secret without the keys, and an endpoint override the egress mode
	// forbids, are refused when the client is built.
	o = newOC(t, interceptor.Funcs{}, namespace("team"), secret(opsNS, "aws", map[string]string{"accessKeyId": "AKIATEST"}), cognitoProvider(), cognitoClaim())
	o.failing("CredentialsUnavailable: the cloud credentials are unavailable")
	override := cognitoProvider()
	override.Spec.Cognito.EndpointOverride = "http://10.0.0.5:5000"
	o = newOC(t, interceptor.Funcs{}, namespace("team"), secret(opsNS, "aws", awsKeys), override, cognitoClaim())
	o.failing("EndpointOverrideForbidden: endpointOverride is not allowed here")

	// A provider of type Cognito without its block.
	broken := cognitoProvider()
	broken.Spec.Cognito = nil
	o = newOC(t, interceptor.Funcs{}, namespace("team"), secret(opsNS, "aws", awsKeys), broken, cognitoClaim())
	o.failing(invalidProvider)
}

// The backend of a Cognito provider derives the issuer and the endpoints, hands
// out the client and refuses the other kinds' clients; it honours an endpoint
// override in allow-private mode.
func TestBackendCognito(t *testing.T) {
	ctx := context.Background()
	f := newFakeCognito()
	override := cognitoProvider()
	override.Spec.Cognito.EndpointOverride = "http://10.0.0.5:5000"
	for name, mode := range map[string]egress.Mode{"strict": egress.ModeStrict, "allow-private": egress.ModeAllowPrivate} {
		t.Run(name, func(t *testing.T) {
			c := fakeClient(t, namespace("team"), secret(opsNS, "aws", awsKeys), override)
			cfg := config(c)
			cfg.EgressMode, cfg.Cognito = mode, fakeFactory(f)
			b, err := cfg.Backend(ctx, "team", ref(kindClusterIdentityProvider, "cog"))
			if err != nil {
				t.Fatal(err)
			}
			defer b.Release()
			if b.Spec.Type != oidcv1alpha1.ProviderCognito || b.UserPoolID != testPool || b.Conn.Endpoint != "" ||
				b.Issuer != "https://cognito-idp.eu-west-1.amazonaws.com/"+testPool || b.Discovery == nil {
				t.Errorf("backend = %+v", b)
			}
			api, err := b.Cognito()
			if mode == egress.ModeStrict {
				if err == nil || !strings.Contains(err.Error(), ReasonEndpointOverrideForbidden) {
					t.Errorf("an endpoint override in strict mode: %v", err)
				}
			} else if err != nil || api == nil {
				t.Errorf("client: %v, %v", api, err)
			}
			if _, err := b.Keycloak(); !errors.Is(err, server.ErrInvalidServer) {
				t.Errorf("a Cognito provider gave a Keycloak client: %v", err)
			}
		})
	}

	// A namespaced provider reads its credentials from its own namespace.
	ns := &oidcv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "cog", UID: "uid-ns", Generation: 1}}
	ns.Spec.ProviderConfig = cognitoProvider().Spec.ProviderConfig
	ns.Spec.Credentials = &cloud.NamespacedCredentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "aws"}}
	cfg := config(fakeClient(t, namespace("team"), secret("team", "aws", awsKeys), ns))
	cfg.Cognito = fakeFactory(f)
	b, err := cfg.Backend(ctx, "team", ref(kindIdentityProvider, "cog"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
	if _, err := b.Cognito(); err != nil {
		t.Errorf("namespaced client: %v", err)
	}
	// A provider of another type has no Cognito client.
	kc := startIDP(t)
	kb, err := config(fakeClient(t, kcObjects(kc)...)).Backend(ctx, "team", ref(kindIdentityProvider, "kc"))
	if err != nil {
		t.Fatal(err)
	}
	defer kb.Release()
	if _, err := kb.Cognito(); !errors.Is(err, server.ErrInvalidServer) {
		t.Errorf("a Keycloak provider gave a Cognito client: %v", err)
	}
}

// The probe describes the user pool and records what it found: the pool, the
// issuer, the endpoints and the CloudResolved condition.
func TestProbeCognito(t *testing.T) {
	ctx := context.Background()
	f := newFakeCognito()
	p := Prober{Config: Config{Cognito: fakeFactory(f)}}
	conn := server.CloudConnection{Credentials: map[string][]byte{"accessKeyId": []byte("AKIATEST"), "secretAccessKey": []byte("x")}}
	srv := cognitoProvider()

	res, err := p.ProbeCloud(ctx, srv, conn)
	want := map[string]string{
		"region": "eu-west-1", "resourceId": testPool, "accountId": "111122223333",
		"issuer": "https://cognito-idp.eu-west-1.amazonaws.com/" + testPool, "endpoint": "team-auth.auth.eu-west-1.amazoncognito.com",
	}
	if err != nil || res.Version != "" || len(res.Discovered) != len(want) {
		t.Fatalf("probe: %+v, %v", res, err)
	}
	for k, v := range want {
		if res.Discovered[k] != v {
			t.Errorf("discovered %s = %q, want %q", k, res.Discovered[k], v)
		}
	}
	if d := srv.Status.Discovery; d == nil || d.TokenEndpoint != "https://team-auth.auth.eu-west-1.amazoncognito.com/oauth2/token" {
		t.Errorf("discovery = %+v", d)
	}
	wantServerCond := func(status metav1.ConditionStatus, reason string) {
		t.Helper()
		got := conditionOf(srv.Status.Conditions, ConditionCloudResolved)
		if got == nil || got.Status != status || got.Reason != reason {
			t.Errorf("CloudResolved = %+v, want %s %s", got, status, reason)
		}
	}
	wantServerCond(metav1.ConditionTrue, ReasonResolved)

	// A pool answered without an ID or ARN is described by the spec.
	f.pool = &cogtypes.UserPoolType{}
	res, err = p.ProbeCloud(ctx, srv, conn)
	if err != nil || res.Discovered["resourceId"] != testPool || res.Discovered["accountId"] != "" {
		t.Errorf("bare pool: %+v, %v", res, err)
	}

	for name, tc := range map[string]struct {
		edit   func(*fakeCognito, *oidcv1alpha1.ClusterIdentityProvider, *server.CloudConnection)
		reason string
		text   string
	}{
		"no such pool": {func(_ *fakeCognito, s *oidcv1alpha1.ClusterIdentityProvider, _ *server.CloudConnection) {
			s.Spec.Cognito.UserPoolID = "eu-west-1_Other"
		}, ReasonTargetNotFound, "the user pool does not exist"},
		"a refused call": {func(f *fakeCognito, _ *oidcv1alpha1.ClusterIdentityProvider, _ *server.CloudConnection) {
			f.failOp["pool"] = errRefused
		}, ReasonCloudError, "the Cognito API refused the request"},
		"a throttled call": {func(f *fakeCognito, _ *oidcv1alpha1.ClusterIdentityProvider, _ *server.CloudConnection) {
			f.failOp["pool"] = errThrottled
		}, ReasonCloudError, "the Cognito API call failed"},
		"an answer without a pool": {func(f *fakeCognito, _ *oidcv1alpha1.ClusterIdentityProvider, _ *server.CloudConnection) {
			f.poolEmpty = true
		}, ReasonCloudError, "the Cognito API answered with an unexpected document"},
		"no cognito block": {func(_ *fakeCognito, s *oidcv1alpha1.ClusterIdentityProvider, _ *server.CloudConnection) {
			s.Spec.Cognito = nil
		}, ReasonCloudError, "the provider has no cognito block"},
		"no credentials": {func(_ *fakeCognito, _ *oidcv1alpha1.ClusterIdentityProvider, c *server.CloudConnection) {
			c.Credentials = nil
		}, ReasonCredentialsUnavailable, "the cloud credentials are unavailable"},
		"an override in strict mode": {func(_ *fakeCognito, s *oidcv1alpha1.ClusterIdentityProvider, _ *server.CloudConnection) {
			s.Spec.Cognito.EndpointOverride = "http://10.0.0.5:5000"
		}, ReasonEndpointOverrideForbidden, "endpointOverride is not allowed here"},
	} {
		f := newFakeCognito()
		srv, conn := cognitoProvider(), conn
		tc.edit(f, srv, &conn)
		_, err := Prober{Config: Config{Cognito: fakeFactory(f)}}.ProbeCloud(ctx, srv, conn)
		var ce *CloudError
		if !errors.As(err, &ce) || ce.Reason != tc.reason || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := conditionOf(srv.Status.Conditions, ConditionCloudResolved); got == nil || got.Status != metav1.ConditionFalse || got.Reason != tc.reason {
			t.Errorf("%s: CloudResolved = %+v", name, got)
		}
		if errors.Is(err, lifecycle.ErrUnreachable) != (name == "a throttled call") {
			t.Errorf("%s: unreachable = %v", name, errors.Is(err, lifecycle.ErrUnreachable))
		}
	}
}

func conditionOf(conds []metav1.Condition, typ string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == typ {
			return &conds[i]
		}
	}
	return nil
}

// recordCloud clears lastProbeTime only when the condition changed, and shows a
// failure that is not one of the categories as a generic one.
func TestRecordCloud(t *testing.T) {
	now := metav1.Now()
	st := &oidcv1alpha1.IdentityProviderStatus{}
	st.LastProbeTime = &now
	recordCloud(st, 1, nil)
	if st.LastProbeTime != nil {
		t.Error("a new condition kept lastProbeTime")
	}
	st.LastProbeTime = &now
	recordCloud(st, 1, nil)
	if st.LastProbeTime == nil {
		t.Error("an unchanged condition cleared lastProbeTime")
	}
	recordCloud(st, 1, errors.New("AKIASECRET"))
	got := conditionOf(st.Conditions, ConditionCloudResolved)
	if got.Status != metav1.ConditionFalse || got.Reason != ReasonCloudError || strings.Contains(got.Message, "AKIA") {
		t.Errorf("condition = %+v", got)
	}
}

// The classifier tells a failed call that may pass by itself from one that will
// not, and an app client that is gone from both.
func TestCognitoErr(t *testing.T) {
	if cognitoErr(nil) != nil {
		t.Error("nil is an error")
	}
	if err := cognitoErr(errNotFound); !errors.Is(err, idpclient.ErrNotFound) || strings.Contains(err.Error(), "AKIA") {
		t.Errorf("not found: %v", err)
	}
	for name, tc := range map[string]struct {
		err       error
		transient bool
	}{
		"throttled":         {errThrottled, true},
		"internal":          {&apiErr{code: "InternalErrorException", status: 500}, true},
		"a server error":    {&apiErr{code: "Other", status: 503}, true},
		"too many requests": {&apiErr{code: "Other", status: 429}, true},
		"a deadline":        {context.DeadlineExceeded, true},
		"cancelled":         {context.Canceled, true},
		"a network error":   {&timeoutError{}, true},
		"refused":           {errRefused, false},
		"denied":            {&apiErr{code: "NotAuthorizedException", status: 400}, false},
	} {
		err := cognitoErr(tc.err)
		var ce *CloudError
		if !errors.As(err, &ce) || ce.transient != tc.transient || errors.Is(err, lifecycle.ErrUnreachable) != tc.transient {
			t.Errorf("%s: %+v", name, err)
		}
		if strings.Contains(err.Error(), "AKIA") {
			t.Errorf("%s: the SDK's text leaked: %v", name, err)
		}
	}
}

// timeoutError is a net.Error.
type timeoutError struct{}

func (*timeoutError) Error() string   { return "i/o timeout to 10.0.0.1" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }

// The default client is the SDK's, which can be closed.
func TestNewCognitoBuildsTheSDKClient(t *testing.T) {
	cg := cognitoProvider().Spec.Cognito
	conn := server.CloudConnection{Credentials: map[string][]byte{"accessKeyId": []byte("AKIATEST"), "secretAccessKey": []byte("x")}}
	creds := &cloud.Credentials{Source: cloud.SourceSecret}
	cl, err := Config{}.newCognito(context.Background(), cg, cloud.ScopeCluster, creds, conn)
	if err != nil || cl == nil || cl.CognitoAPI == nil {
		t.Fatalf("client: %v, %v", cl, err)
	}
	cl.CloseIdleConnections()
	(&cognitoClient{}).CloseIdleConnections()
	if NewCognito(aws.Config{Region: "eu-west-1"}) == nil {
		t.Error("no client")
	}
	// A namespaced provider cannot use workload identity.
	if _, err := (Config{}).newCognito(context.Background(), cg, cloud.ScopeNamespaced, nil, conn); err == nil {
		t.Error("a namespaced provider used workload identity")
	}
}

func TestCognitoDerivedEndpoints(t *testing.T) {
	cg := &oidcv1alpha1.CognitoConfig{AWSClusterBlock: cloud.AWSClusterBlock{AWSBlock: cloud.AWSBlock{Region: "us-east-1"}}, UserPoolID: "us-east-1_X", Domain: "login.example.com"}
	d := cognitoDiscovery(cg)
	if d.AuthorizationEndpoint != "https://login.example.com/oauth2/authorize" || d.JWKSURI != "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_X/.well-known/jwks.json" {
		t.Errorf("discovery = %+v", d)
	}
}
