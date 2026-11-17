//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

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
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/controller"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// noEvents is an events.EventRecorder that drops what it is told.
type noEvents struct{}

// Eventf implements events.EventRecorder.
func (noEvents) Eventf(_, _ runtime.Object, _, _, _, _ string, _ ...any) {}

// controllerClient is a fake Kubernetes API server for the controller: the
// claim, the provider and the Secrets it reads live there, the Keycloak is real.
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

// An OidcClient on a real Keycloak is made Ready by the controller, its binding
// Secret holds the client id and the client's secret as Keycloak knows them, and
// deleting the claim removes the client from Keycloak.
func TestOidcClientControllerOnKeycloak(t *testing.T) {
	ctx := t.Context()
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	const ns = "team"
	name := "web-" + hex.EncodeToString(raw)

	provider := &oidcv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "kc", UID: "uid-kc", Generation: 1},
	}
	provider.Spec.ProviderConfig = oidcv1alpha1.ProviderConfig{
		Type:          oidcv1alpha1.ProviderKeycloak,
		Issuer:        oidcv1alpha1.HTTPSURL(baseURL + "/realms/" + realm),
		Keycloak:      &oidcv1alpha1.KeycloakConfig{BaseURL: oidcv1alpha1.HTTPSURL(baseURL), Realm: realm},
		AllowedScopes: []oidcv1alpha1.Scope{"openid", "profile"},
	}
	provider.Spec.AdminCredentialsSecretRef = &common.AdminSecretRef{Name: "admin"}
	provider.Spec.TLS = &common.TLS{CABundle: &common.CABundle{ConfigMapRef: &common.KeyReference{Name: "ca"}}}

	claim := &oidcv1alpha1.OidcClient{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name, UID: types.UID("uid-" + name), Generation: 1, CreationTimestamp: metav1.Now(),
	}}
	claim.Spec.ServerRef = common.ServerRef{Kind: "IdentityProvider", Name: "kc"}
	claim.Spec.RedirectURIs = []oidcv1alpha1.RedirectURI{"https://app.example.org/callback"}
	claim.Spec.Scopes = []oidcv1alpha1.Scope{"openid", "profile"}

	c := controllerClient(t,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "admin"},
			Data:       map[string][]byte{"clientId": []byte(operatorClient), "clientSecret": []byte(opSecret)},
		},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ca"}, Data: map[string]string{"ca.crt": string(caPEM)}},
		provider, claim)
	r := &controller.ClientReconciler{Config: controller.Config{
		Client: c, APIReader: c, OperatorNamespace: "operator-ns", Recorder: noEvents{}, ManagedBy: "operator-oidc",
		// The tests dial directly: the egress policy refuses the loopback address.
		HostDialer: func(*url.URL) (egress.DialFunc, error) { return direct, nil },
	}}
	key := client.ObjectKey{Namespace: ns, Name: name}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	clientID := idpclient.KeycloakClientID(ns, name)
	t.Cleanup(func() {
		// Whatever the test left behind.
		if id, err := clientUUID(clientID); err == nil {
			_, _, _ = must(http.MethodDelete, "/"+realm+"/clients/"+id, nil, 204, 404)
		}
	})

	reconcile()
	var got oidcv1alpha1.OidcClient
	if err := c.Get(ctx, key, &got); err != nil {
		t.Fatal(err)
	}
	ready := meta.FindStatusCondition(got.Status.Conditions, conditions.Ready)
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("Ready = %+v", ready)
	}
	id, err := clientUUID(clientID)
	if err != nil {
		t.Fatalf("the client is not in Keycloak: %v", err)
	}
	if got.Status.ExternalID != id || got.Status.ExternalName != clientID {
		t.Errorf("status = %q %q, want %q %q", got.Status.ExternalID, got.Status.ExternalName, id, clientID)
	}

	var binding corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: got.GetBindingSecretName()}, &binding); err != nil {
		t.Fatalf("binding Secret: %v", err)
	}
	if string(binding.Data["clientId"]) != clientID || binding.Data["issuer"] == nil {
		t.Errorf("binding keys = %v", binding.Data)
	}
	data, _, err := must(http.MethodGet, "/"+realm+"/clients/"+id+"/client-secret", nil, 200)
	if err != nil {
		t.Fatal(err)
	}
	var secret struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &secret); err != nil {
		t.Fatal(err)
	}
	if secret.Value == "" || string(binding.Data["clientSecret"]) != secret.Value {
		t.Error("the binding Secret does not hold the client's secret")
	}

	// Deleting the claim deletes the client.
	if err := c.Delete(ctx, &got); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if err := c.Get(ctx, key, &oidcv1alpha1.OidcClient{}); !apierrors.IsNotFound(err) {
		t.Errorf("the claim is still there: %v", err)
	}
	if _, err := clientUUID(clientID); err == nil {
		t.Errorf("the client %s is still in Keycloak", clientID)
	}
}
