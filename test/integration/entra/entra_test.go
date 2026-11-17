//go:build integration && entra

package entra

// The Entra backend (NKoidc-2) against a fake Microsoft Graph and a fake Entra
// token endpoint: the probe and the lifecycle of an OidcClient through the real
// controller, azidentity (client secret credential) and the egress policy.
// There is no Graph emulator, so both fakes are in this test, served over TLS at
// a private (non-loopback) address with EGRESS_MODE=allow-private in this test's
// own wiring (pkg/egress blocks loopback in both modes). This checks the shapes
// of the Graph calls, the token request and the lifecycle (create, drift,
// rotation with overlap, delete). It does not check what real Graph and Entra
// do: admin consent, conditional access, Workload Identity federation, the
// permission model (Application.ReadWrite.OwnedBy), throttling, or the
// replication delay after a create (docs/nfrs, the NFR on the cloud emulators).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/controller"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

const (
	tenant    = "00000000-0000-4000-8000-000000000001"
	opsNS     = "operator-oidc-system"
	graphTok  = "entra-fake-token"
	clientKey = "11111111-1111-4111-8111-111111111111"
)

// noEvents is an events.EventRecorder that drops what it is told.
type noEvents struct{}

// Eventf implements events.EventRecorder.
func (noEvents) Eventf(_, _ runtime.Object, _, _, _, _ string, _ ...any) {}

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

// privateIP is an IPv4 address of this host that the egress policy treats as
// private and that is not loopback.
func privateIP(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip := n.IP.To4(); ip != nil && ip.IsPrivate() {
				return ip
			}
		}
	}
	t.Fatal("this host has no private IPv4 address to serve the fakes on")
	return nil
}

// tlsFor is a self-signed certificate for ip and the pool that trusts it.
func tlsFor(t *testing.T, ip net.IP) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake entra"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{ip}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	pemKey, _ := x509.MarshalECPrivateKey(key)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pemKey}))
	if err != nil {
		t.Fatal(err)
	}
	return pair, pool
}

// fakeTenant is an Entra authority (the tenant's OpenID configuration and the
// client credentials token endpoint) and the part of Microsoft Graph v1.0 the
// operator uses (applications and their passwords), on one server.
type fakeTenant struct {
	srv   *httptest.Server
	roots *x509.CertPool
	mu    sync.Mutex
	apps  map[string]map[string]any
	// unique maps a uniqueName to the object ID of the application made for it.
	unique map[string]string
	n      int
	tokens int
	// calls are "METHOD /path" of every Graph call.
	calls []string
	// badToken makes the token endpoint refuse, as for a wrong client secret.
	badToken bool
}

func startTenant(t *testing.T) *fakeTenant {
	t.Helper()
	ip := privateIP(t)
	pair, roots := tlsFor(t, ip)
	f := &fakeTenant{apps: map[string]map[string]any{}, unique: map[string]string{}, roots: roots}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	l, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.srv.Listener.Close()
	f.srv.Listener = l
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTenant) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	base := f.srv.URL + "/" + tenant
	switch {
	case strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration"):
		_, _ = io.WriteString(w, `{"issuer":"`+base+`/v2.0","authorization_endpoint":"`+base+`/oauth2/v2.0/authorize","token_endpoint":"`+base+`/oauth2/v2.0/token"}`)
		return
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		_ = r.ParseForm()
		if f.badToken || r.PostForm.Get("client_secret") != "entra-client-secret" || r.PostForm.Get("client_id") != clientKey {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		f.tokens++
		_, _ = io.WriteString(w, `{"access_token":"`+graphTok+`","token_type":"Bearer","expires_in":3600,"ext_expires_in":3600}`)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1.0/") || r.Header.Get("Authorization") != "Bearer "+graphTok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.graph(w, r)
}

func (f *fakeTenant) graph(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1.0/applications"), "/")[1:]
	var in map[string]any
	if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
		_ = json.Unmarshal(raw, &in)
	}
	out := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	// The alternate key: applications(uniqueName='name'). A PATCH with Prefer:
	// create-if-missing is an upsert (201 for a new application, 204 for an
	// existing one); a GET reads it.
	if rest := strings.TrimPrefix(r.URL.Path, "/v1.0/applications"); strings.HasPrefix(rest, "(uniqueName='") && strings.HasSuffix(rest, "')") {
		name := strings.TrimSuffix(strings.TrimPrefix(rest, "(uniqueName='"), "')")
		id := f.unique[name]
		switch {
		case r.Method == http.MethodGet && f.apps[id] != nil:
			out(http.StatusOK, f.apps[id])
		case r.Method == http.MethodPatch && f.apps[id] != nil:
			for k, v := range in {
				f.apps[id][k] = v
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch && r.Header.Get("Prefer") == "create-if-missing":
			f.n++
			id = fmt.Sprintf("a0000000-0000-4000-8000-%012d", f.n)
			in["id"], in["appId"], in["uniqueName"], in["passwordCredentials"] = id, fmt.Sprintf("b0000000-0000-4000-8000-%012d", f.n), name, []any{}
			f.apps[id], f.unique[name] = in, id
			out(http.StatusCreated, in)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	switch {
	case len(parts) == 0 && r.Method == http.MethodGet:
		out(http.StatusOK, map[string]any{"value": []any{}})
	case len(parts) == 0 && r.Method == http.MethodPost:
		f.n++
		id := fmt.Sprintf("a0000000-0000-4000-8000-%012d", f.n)
		in["id"], in["appId"], in["passwordCredentials"] = id, fmt.Sprintf("b0000000-0000-4000-8000-%012d", f.n), []any{}
		f.apps[id] = in
		out(http.StatusCreated, in)
	case len(parts) >= 1 && f.apps[parts[0]] == nil:
		w.WriteHeader(http.StatusNotFound)
	case len(parts) == 1 && r.Method == http.MethodGet:
		out(http.StatusOK, f.apps[parts[0]])
	case len(parts) == 1 && r.Method == http.MethodPatch:
		for k, v := range in {
			f.apps[parts[0]][k] = v
		}
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 1 && r.Method == http.MethodDelete:
		delete(f.apps, parts[0])
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2 && parts[1] == "addPassword" && r.Method == http.MethodPost:
		f.n++
		pc, _ := in["passwordCredential"].(map[string]any)
		key := fmt.Sprintf("c0000000-0000-4000-8000-%012d", f.n)
		// Graph keeps the first three characters of a secret readable (the hint).
		text := fmt.Sprintf("s%d-secret", f.n)
		list, _ := f.apps[parts[0]]["passwordCredentials"].([]any)
		f.apps[parts[0]]["passwordCredentials"] = append(list, map[string]any{"keyId": key, "displayName": pc["displayName"], "hint": text[:3]})
		out(http.StatusOK, map[string]any{"keyId": key, "secretText": text, "displayName": pc["displayName"], "hint": text[:3]})
	case len(parts) == 2 && parts[1] == "removePassword" && r.Method == http.MethodPost:
		list, _ := f.apps[parts[0]]["passwordCredentials"].([]any)
		kept := []any{}
		for _, p := range list {
			if p.(map[string]any)["keyId"] != in["keyId"] {
				kept = append(kept, p)
			}
		}
		if len(kept) == len(list) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.apps[parts[0]]["passwordCredentials"] = kept
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeTenant) app(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.apps[id]
}

func (f *fakeTenant) passwords(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	list, _ := f.apps[id]["passwordCredentials"].([]any)
	for _, p := range list {
		out = append(out, p.(map[string]any)["keyId"].(string))
	}
	return out
}

func (f *fakeTenant) tokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens
}

func (f *fakeTenant) saw(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.calls, call)
}

// harness is the provider on the fake tenant and the operator's configuration.
type harness struct {
	f        *fakeTenant
	keys     map[string][]byte
	provider *oidcv1alpha1.ClusterIdentityProvider
	now      time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	for _, k := range []string{"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_AUTHORITY_HOST", "AZURE_CLIENT_SECRET"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	f := startTenant(t)
	h := &harness{f: f, now: time.Now(), keys: map[string][]byte{cloud.KeyAzureClientID: []byte(clientKey), cloud.KeyAzureClientSecret: []byte("entra-client-secret")}}
	h.provider = &oidcv1alpha1.ClusterIdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "entra", UID: "uid-entra", Generation: 1}}
	h.provider.Spec.ProviderConfig = oidcv1alpha1.ProviderConfig{
		Type: oidcv1alpha1.ProviderEntra, AllowedScopes: []oidcv1alpha1.Scope{"openid", "profile"},
		Entra: &oidcv1alpha1.EntraConfig{AzureClusterBlock: cloud.AzureClusterBlock{
			AzureBlock: cloud.AzureBlock{TenantID: tenant}, EndpointOverride: f.srv.URL,
		}},
	}
	h.provider.Spec.Credentials = &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "azure", Namespace: opsNS}}
	h.provider.Spec.AllowedNamespaces = common.AllowedNamespaces{From: common.NamespacesAll}
	return h
}

func (h *harness) secret() *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: opsNS, Name: "azure"}, Data: h.keys}
}

func (h *harness) config(c client.Client) controller.Config {
	mode := egress.ModeAllowPrivate
	return controller.Config{
		Client: c, APIReader: c, OperatorNamespace: opsNS, Recorder: noEvents{}, ManagedBy: "operator-oidc",
		Egress: egress.NewPolicy(mode), EgressMode: mode, RootCAs: h.f.roots, Now: func() time.Time { return h.now },
	}
}

// The probe gets a token from the fake authority and lists applications through
// Graph; a refused token is a fixed text, and an endpoint override is refused
// in strict mode.
func TestEntraProbeAgainstTheFakeTenant(t *testing.T) {
	ctx := t.Context()
	h := newHarness(t)
	conn := server.CloudConnection{Credentials: h.keys}
	p := controller.Prober{Config: h.config(controllerClient(t))}

	res, err := p.ProbeCloud(ctx, h.provider, conn)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	d := res.Discovered
	if d["resourceId"] != tenant || d["endpoint"] != strings.TrimPrefix(h.f.srv.URL, "https://") || len(d) != 2 {
		t.Errorf("discovered = %v", d)
	}
	if !h.f.saw("GET /v1.0/applications") || h.f.tokenCount() == 0 {
		t.Errorf("graph called = %v, tokens = %d", h.f.saw("GET /v1.0/applications"), h.f.tokenCount())
	}
	if disc := h.provider.Status.Discovery; disc == nil || disc.TokenEndpoint != h.f.srv.URL+"/"+tenant+"/oauth2/v2.0/token" {
		t.Errorf("discovery = %+v", disc)
	}

	h.f.mu.Lock()
	h.f.badToken = true
	h.f.mu.Unlock()
	bad := controller.Prober{Config: h.config(controllerClient(t))}
	if _, err = bad.ProbeCloud(ctx, h.provider, conn); err == nil || strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("a refused token: %v", err)
	}

	strict := controller.Prober{Config: h.config(controllerClient(t))}
	strict.Config.EgressMode = egress.ModeStrict
	strict.Config.Egress = egress.NewPolicy(egress.ModeStrict)
	if _, err = strict.ProbeCloud(ctx, h.provider, conn); err == nil || !strings.Contains(err.Error(), "endpointOverride is not allowed here") {
		t.Errorf("an override in strict mode: %v", err)
	}
}

// An OidcClient on an Entra provider is made Ready by the controller, its
// binding Secret holds the application ID and the secret, a change of its
// redirect URIs reaches the application, a rotation overlaps and retires the
// old secret, and deleting the claim removes the application.
func TestOidcClientControllerOnEntra(t *testing.T) {
	ctx := t.Context()
	h := newHarness(t)
	const ns = "team"
	const name = "web"

	claim := &oidcv1alpha1.OidcClient{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns, Name: name, UID: types.UID("uid-" + name), Generation: 1, CreationTimestamp: metav1.NewTime(h.now.Add(-time.Hour)),
	}}
	claim.Spec.ServerRef = common.ServerRef{Kind: "ClusterIdentityProvider", Name: "entra"}
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
	bindingSecret := func(got oidcv1alpha1.OidcClient) corev1.Secret {
		t.Helper()
		var s corev1.Secret
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: got.GetBindingSecretName()}, &s); err != nil {
			t.Fatalf("binding Secret: %v", err)
		}
		return s
	}

	reconcile()
	got := get()
	if ready := meta.FindStatusCondition(got.Status.Conditions, conditions.Ready); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("Ready = %+v", ready)
	}
	id := got.Status.ExternalID
	if id == "" || got.Status.ExternalName != idpclient.EntraAppName(ns, name) {
		t.Fatalf("status = %q %q", got.Status.ExternalID, got.Status.ExternalName)
	}
	app := h.f.app(id)
	web, _ := app["web"].(map[string]any)
	if app["displayName"] != got.Status.ExternalName || app["signInAudience"] != "AzureADMyOrg" ||
		fmt.Sprint(web["redirectUris"]) != "[https://app.example.org/callback]" || len(h.f.passwords(id)) != 1 {
		t.Errorf("application = %v", app)
	}
	binding := bindingSecret(got)
	if string(binding.Data["clientId"]) != app["appId"] || !strings.HasSuffix(string(binding.Data["clientSecret"]), "-secret") ||
		string(binding.Data["issuer"]) != h.f.srv.URL+"/"+tenant+"/v2.0" ||
		string(binding.Data["tokenEndpoint"]) != h.f.srv.URL+"/"+tenant+"/oauth2/v2.0/token" {
		t.Errorf("binding keys = %v", binding.Data)
	}

	// A changed redirect URI reaches the application, and its secret stays.
	got.Spec.RedirectURIs = []oidcv1alpha1.RedirectURI{"https://app.example.org/other"}
	if err := c.Update(ctx, &got); err != nil {
		t.Fatal(err)
	}
	reconcile()
	web, _ = h.f.app(id)["web"].(map[string]any)
	if fmt.Sprint(web["redirectUris"]) != "[https://app.example.org/other]" || !h.f.saw("PATCH /v1.0/applications/"+id) {
		t.Errorf("application after the update = %v", h.f.app(id))
	}
	if again := bindingSecret(get()); string(again.Data["clientSecret"]) != string(binding.Data["clientSecret"]) {
		t.Error("the secret changed with the update")
	}

	// A rotation adds a second secret and keeps the first through the grace
	// period; afterwards only the new one is left.
	before := h.f.passwords(id)
	got = get()
	got.Annotations = map[string]string{lifecycle.AnnotationRotate: "1"}
	if err := c.Update(ctx, &got); err != nil {
		t.Fatal(err)
	}
	reconcile()
	during := h.f.passwords(id)
	rotated := bindingSecret(get())
	if len(during) != 2 || string(rotated.Data["clientSecret"]) == string(binding.Data["clientSecret"]) {
		t.Fatalf("passwords before = %v, during = %v", before, during)
	}
	h.now = h.now.Add(2 * time.Hour)
	reconcile()
	if after := h.f.passwords(id); len(after) != 1 || after[0] != during[1] {
		t.Errorf("passwords after the grace period = %v, want only %s", after, during[1])
	}

	// Deleting the claim deletes the application.
	got = get()
	if err := c.Delete(ctx, &got); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if err := c.Get(ctx, key, &oidcv1alpha1.OidcClient{}); !apierrors.IsNotFound(err) {
		t.Errorf("the claim is still there: %v", err)
	}
	if h.f.app(id) != nil {
		t.Errorf("the application %s is still in the tenant", id)
	}
}
