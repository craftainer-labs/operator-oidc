package controller

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
)

const opsNS = "operator-ns"

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := oidcv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// fakeClient serves objs the way an API server does: the cluster provider kind
// is cluster-scoped.
func fakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fakeClientWith(t, interceptor.Funcs{}, objs...)
}

// fakeClientWith is fakeClient with hooks into its calls.
func fakeClientWith(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	m := meta.NewDefaultRESTMapper(nil)
	m.Add(oidcv1alpha1.GroupVersion.WithKind("ClusterIdentityProvider"), meta.RESTScopeRoot)
	m.Add(oidcv1alpha1.GroupVersion.WithKind("IdentityProvider"), meta.RESTScopeNamespace)
	m.Add(corev1.SchemeGroupVersion.WithKind("Secret"), meta.RESTScopeNamespace)
	m.Add(corev1.SchemeGroupVersion.WithKind("ConfigMap"), meta.RESTScopeNamespace)
	m.Add(corev1.SchemeGroupVersion.WithKind("Namespace"), meta.RESTScopeRoot)
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithRESTMapper(m).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
}

// direct dials without the egress policy: the fakes listen on loopback, which
// the policy refuses (TestRealPolicyRefusesLoopback shows that).
func direct(_ *url.URL) (egress.DialFunc, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}, nil
}

// idp is a fake identity provider: Keycloak's token and clients endpoints and a
// discovery document, for the realm "main".
type idp struct {
	srv *httptest.Server
	ca  []byte
	// tokenStatus is the answer to a token request; 200 when zero.
	tokenStatus int
	mu          sync.Mutex
	tokens      int
}

func (f *idp) issuer() string { return f.srv.URL + "/realms/main" }

func (f *idp) tokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens
}

func startIdP(t *testing.T) *idp {
	t.Helper()
	f := &idp{}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/realms/main/protocol/openid-connect/token":
			f.mu.Lock()
			f.tokens++
			f.mu.Unlock()
			if f.tokenStatus != 0 {
				w.WriteHeader(f.tokenStatus)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"t","expires_in":300}`)
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/main/clients":
			_, _ = io.WriteString(w, `[]`)
		case r.URL.Path == "/realms/main/.well-known/openid-configuration":
			b, _ := json.Marshal(map[string]string{
				"issuer": f.issuer(), "token_endpoint": f.issuer() + "/protocol/openid-connect/token",
				"authorization_endpoint": f.issuer() + "/protocol/openid-connect/auth",
				"jwks_uri":               f.issuer() + "/protocol/openid-connect/certs",
				"userinfo_endpoint":      f.issuer() + "/protocol/openid-connect/userinfo",
			})
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return f
}

func secret(ns, name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Data: map[string][]byte{}}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	return s
}

func caConfigMap(ns string, f *idp) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ca"},
		Data:       map[string]string{"ca.crt": string(f.ca)},
	}
}

func namespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

var tlsCA = &common.TLS{CABundle: &common.CABundle{ConfigMapRef: &common.KeyReference{Name: "ca"}}}

// keycloakProvider is a namespaced provider of type Keycloak on f.
func keycloakProvider(ns string, f *idp) *oidcv1alpha1.IdentityProvider {
	p := &oidcv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "kc", UID: "uid-kc", Generation: 1}}
	p.Spec.ProviderConfig = oidcv1alpha1.ProviderConfig{
		Type: oidcv1alpha1.ProviderKeycloak, Issuer: oidcv1alpha1.HTTPSURL(f.issuer()),
		Keycloak: &oidcv1alpha1.KeycloakConfig{BaseURL: oidcv1alpha1.HTTPSURL(f.srv.URL), Realm: "main"},
	}
	p.Spec.AdminCredentialsSecretRef = common.AdminSecretRef{Name: "admin"}
	p.Spec.TLS = tlsCA
	return p
}

// clusterKeycloak is a cluster provider of type Keycloak on f that every
// namespace may use.
func clusterKeycloak(f *idp) *oidcv1alpha1.ClusterIdentityProvider {
	p := &oidcv1alpha1.ClusterIdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "kc", UID: "uid-ckc", Generation: 1}}
	p.Spec.ProviderConfig = keycloakProvider("", f).Spec.ProviderConfig
	p.Spec.AdminCredentialsSecretRef = common.AdminSecretRef{Name: "admin", Namespace: opsNS}
	p.Spec.TLS = tlsCA
	p.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesAll}
	return p
}

// dcrProvider is a namespaced provider of type DynamicRegistration.
func dcrProvider(ns, endpoint string) *oidcv1alpha1.IdentityProvider {
	p := &oidcv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "dcr", UID: "uid-dcr", Generation: 1}}
	p.Spec.ProviderConfig = oidcv1alpha1.ProviderConfig{
		Type: oidcv1alpha1.ProviderDynamicRegistration, Issuer: "https://idp.example",
		DynamicRegistration: &oidcv1alpha1.DynamicRegistrationConfig{RegistrationEndpoint: oidcv1alpha1.HTTPSURL(endpoint)},
	}
	p.Spec.AdminCredentialsSecretRef = common.AdminSecretRef{Name: "admin"}
	return p
}

func ref(kind, name string) common.ServerRef { return common.ServerRef{Kind: kind, Name: name} }
