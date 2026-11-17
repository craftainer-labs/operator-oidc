//go:build integration && cognito

package cognito

// The Cognito backend (NKoidc-1) against moto server: the user pool and app
// client calls of the controller and of the probe. moto is reached at a private
// container address, never loopback, with EGRESS_MODE=allow-private in this
// test's own wiring (pkg/egress blocks loopback in both modes). moto does not
// serve the hosted UI or the OAuth endpoints, enforce IAM, or implement the
// multi-secret API of the SDK, and it is not IRSA: this checks the shapes of
// the control-plane calls and the lifecycle, not credentials or sign-in
// (docs/nfrs, the NFR on cloud credentials and egress).

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cogtypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/controller"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// noEvents is an events.EventRecorder that drops what it is told.
type noEvents struct{}

// Eventf implements events.EventRecorder.
func (noEvents) Eventf(_, _ runtime.Object, _, _, _, _ string, _ ...any) {}

// controllerClient is a fake Kubernetes API server for the controller: the
// claim, the provider and the Secrets it reads live there, moto is real.
func controllerClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := oidcv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := meta.NewDefaultRESTMapper(nil)
	m.Add(oidcv1alpha1.GroupVersion.WithKind("ClusterIdentityProvider"), meta.RESTScopeRoot)
	m.Add(oidcv1alpha1.GroupVersion.WithKind("IdentityProvider"), meta.RESTScopeNamespace)
	m.Add(oidcv1alpha1.GroupVersion.WithKind("OidcClient"), meta.RESTScopeNamespace)
	m.Add(corev1.SchemeGroupVersion.WithKind("Secret"), meta.RESTScopeNamespace)
	m.Add(corev1.SchemeGroupVersion.WithKind("ConfigMap"), meta.RESTScopeNamespace)
	m.Add(corev1.SchemeGroupVersion.WithKind("Namespace"), meta.RESTScopeRoot)
	return fake.NewClientBuilder().WithScheme(scheme).WithRESTMapper(m).WithObjects(objs...).
		WithStatusSubresource(&oidcv1alpha1.OidcClient{}).Build()
}

const (
	motoRegion = "us-east-1"
	motoOpsNS  = "operator-oidc-system"
)

// motoEndpoint is the moto server, from MOTO_ENDPOINT (http://<private ip>:5000).
func motoEndpoint(t *testing.T) string {
	t.Helper()
	v := os.Getenv("MOTO_ENDPOINT")
	if v == "" {
		t.Fatal("MOTO_ENDPOINT is not set; see test/integration/README.md")
	}
	return v
}

func motoSuffix(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// motoHarness is a Cognito provider on moto, the operator's configuration for
// it and the test's own client of moto, built the way the operator's are.
type motoHarness struct {
	api      *cip.Client
	endpoint string
	poolID   string
	keys     map[string][]byte
	provider *oidcv1alpha1.ClusterIdentityProvider
}

func newMotoHarness(t *testing.T) *motoHarness {
	t.Helper()
	ctx := t.Context()
	endpoint := motoEndpoint(t)
	keys := map[string][]byte{cloud.KeyAWSAccessKeyID: []byte("test"), cloud.KeyAWSSecretAccessKey: []byte("test")}
	e := cloud.NewEgress(egress.ModeAllowPrivate, nil)
	acfg, err := e.AWS(ctx, cloud.ScopeCluster,
		cloud.AWSClusterBlock{AWSBlock: cloud.AWSBlock{Region: motoRegion}, EndpointOverride: endpoint},
		&cloud.Credentials{Source: cloud.SourceSecret}, keys)
	if err != nil {
		t.Fatalf("AWS client: %v", err)
	}
	h := &motoHarness{api: cip.NewFromConfig(acfg), endpoint: endpoint, keys: keys}
	pool, err := h.api.CreateUserPool(ctx, &cip.CreateUserPoolInput{PoolName: aws.String("pool-" + motoSuffix(t))})
	if err != nil {
		t.Fatalf("create the user pool in moto: %v", err)
	}
	h.poolID = aws.ToString(pool.UserPool.Id)
	t.Cleanup(func() {
		_, _ = h.api.DeleteUserPool(ctx, &cip.DeleteUserPoolInput{UserPoolId: aws.String(h.poolID)})
	})

	h.provider = &oidcv1alpha1.ClusterIdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "cognito", UID: "uid-cognito", Generation: 1}}
	h.provider.Spec.ProviderConfig = oidcv1alpha1.ProviderConfig{
		Type: oidcv1alpha1.ProviderCognito, AllowedScopes: []oidcv1alpha1.Scope{"openid", "profile"},
		Cognito: &oidcv1alpha1.CognitoConfig{
			AWSClusterBlock: cloud.AWSClusterBlock{AWSBlock: cloud.AWSBlock{Region: motoRegion}, EndpointOverride: endpoint},
			UserPoolID:      h.poolID, Domain: "team-auth",
		},
	}
	h.provider.Spec.Credentials = &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "aws", Namespace: motoOpsNS}}
	h.provider.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesAll}
	return h
}

func (h *motoHarness) secret() *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: motoOpsNS, Name: "aws"}, Data: h.keys}
}

func (h *motoHarness) config(c client.Client) controller.Config {
	mode := egress.ModeAllowPrivate
	return controller.Config{
		Client: c, APIReader: c, OperatorNamespace: motoOpsNS, Recorder: noEvents{}, ManagedBy: "operator-oidc",
		Egress: egress.NewPolicy(mode), EgressMode: mode,
	}
}

// The probe describes the user pool and records it; a pool that does not exist
// fails with a coarse "does not exist", and an endpoint override is refused in strict mode.
func TestCognitoProbeAgainstMoto(t *testing.T) {
	ctx := t.Context()
	h := newMotoHarness(t)
	conn := server.CloudConnection{Credentials: h.keys}
	p := controller.Prober{Config: h.config(controllerClient(t))}

	res, err := p.ProbeCloud(ctx, h.provider, conn)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	d := res.Discovered
	if d["resourceId"] != h.poolID || d["region"] != motoRegion || d["endpoint"] == "" || len(d) != 3 {
		t.Errorf("discovered = %v", d)
	}

	missing := h.provider.DeepCopy()
	missing.Spec.Cognito.UserPoolID = motoRegion + "_doesnotexist"
	if _, err = p.ProbeCloud(ctx, missing, conn); err == nil || !strings.Contains(err.Error(), "the user pool does not exist") {
		t.Errorf("a missing pool: %v", err)
	}

	strict := controller.Prober{Config: h.config(controllerClient(t))}
	strict.Config.EgressMode = egress.ModeStrict
	strict.Config.Egress = egress.NewPolicy(egress.ModeStrict)
	forbidden := h.provider.DeepCopy()
	if _, err = strict.ProbeCloud(ctx, forbidden, conn); err == nil || !strings.Contains(err.Error(), "endpointOverride is not allowed here") {
		t.Errorf("an override in strict mode: %v", err)
	}
}

// An OidcClient on a Cognito provider is made Ready by the controller, its
// binding Secret holds the app client ID and the secret moto knows, a change of
// its redirect URIs reaches the app client, and deleting the claim removes it.
func TestOidcClientControllerOnCognito(t *testing.T) {
	ctx := t.Context()
	h := newMotoHarness(t)
	const ns = "team"
	name := "web-" + motoSuffix(t)

	claim := &oidcv1alpha1.OidcClient{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name, UID: types.UID("uid-" + name), Generation: 1, CreationTimestamp: metav1.Now(),
	}}
	claim.Spec.ServerRef = common.ServerRef{Kind: "ClusterIdentityProvider", Name: "cognito"}
	claim.Spec.RedirectURIs = []oidcv1alpha1.RedirectURI{"https://app.example.org/callback"}
	claim.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "profile"}

	c := controllerClient(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, h.secret(), h.provider, claim)
	r := &controller.ClientReconciler{Config: h.config(c)}
	key := client.ObjectKey{Namespace: ns, Name: name}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	get := func() oidcv1alpha1.OidcClient {
		t.Helper()
		var got oidcv1alpha1.OidcClient
		if err := c.Get(ctx, key, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	appClient := func(id string) (*cogtypes.UserPoolClientType, error) {
		out, err := h.api.DescribeUserPoolClient(ctx, &cip.DescribeUserPoolClientInput{UserPoolId: aws.String(h.poolID), ClientId: aws.String(id)})
		if err != nil {
			return nil, err
		}
		return out.UserPoolClient, nil
	}

	reconcile()
	got := get()
	if ready := meta.FindStatusCondition(got.Status.Conditions, conditions.Ready); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("Ready = %+v", ready)
	}
	id := got.Status.ExternalID
	if id == "" || got.Status.ExternalName != idpclient.CognitoClientName(ns, name) {
		t.Fatalf("status = %q %q", got.Status.ExternalID, got.Status.ExternalName)
	}
	t.Cleanup(func() {
		_, _ = h.api.DeleteUserPoolClient(ctx, &cip.DeleteUserPoolClientInput{UserPoolId: aws.String(h.poolID), ClientId: aws.String(id)})
	})
	app, err := appClient(id)
	if err != nil {
		t.Fatalf("the app client is not in moto: %v", err)
	}
	if aws.ToString(app.ClientName) != got.Status.ExternalName || aws.ToString(app.ClientSecret) == "" ||
		!slices.Equal(app.CallbackURLs, []string{"https://app.example.org/callback"}) {
		t.Errorf("app client = %+v", app)
	}

	var binding corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: got.GetBindingSecretName()}, &binding); err != nil {
		t.Fatalf("binding Secret: %v", err)
	}
	if string(binding.Data["clientId"]) != id || string(binding.Data["clientSecret"]) != aws.ToString(app.ClientSecret) ||
		string(binding.Data["issuer"]) != "https://cognito-idp."+motoRegion+".amazonaws.com/"+h.poolID ||
		string(binding.Data["authorizationEndpoint"]) != "https://team-auth.auth."+motoRegion+".amazoncognito.com/oauth2/authorize" {
		t.Errorf("binding keys = %v", binding.Data)
	}

	// A changed redirect URI reaches the app client, and its secret stays.
	got.Spec.RedirectURIs = []oidcv1alpha1.RedirectURI{"https://app.example.org/other"}
	if err := c.Update(ctx, &got); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if app, err = appClient(id); err != nil || !slices.Equal(app.CallbackURLs, []string{"https://app.example.org/other"}) {
		t.Errorf("app client after the update = %+v, %v", app, err)
	}
	var again corev1.Secret
	if err := c.Get(ctx, client.ObjectKeyFromObject(&binding), &again); err != nil || string(again.Data["clientSecret"]) != string(binding.Data["clientSecret"]) {
		t.Errorf("the secret changed with the update: %v", err)
	}

	// Deleting the claim deletes the app client.
	got = get()
	if err := c.Delete(ctx, &got); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if err := c.Get(ctx, key, &oidcv1alpha1.OidcClient{}); !apierrors.IsNotFound(err) {
		t.Errorf("the claim is still there: %v", err)
	}
	if _, err := appClient(id); err == nil {
		t.Errorf("the app client %s is still in moto", id)
	}
}
