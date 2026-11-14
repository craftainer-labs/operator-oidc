//go:build integration

// Package integration runs the backend clients of internal/idpclient against a
// real Keycloak (see README.md). It is behind the build tag integration, so
// `go test ./...` and the coverage gate of `make test` never see it.
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"

	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

const (
	realm = "operator-it"
	// The operator's service account in the realm.
	operatorClient = "operator"
	// A PKCE code challenge (RFC 7636, appendix B).
	challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

var (
	baseURL  string
	caPEM    []byte
	opSecret string
	adminUse string
	adminPw  string
	httpc    *http.Client
)

func direct(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "integration setup:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func readFile(name string) ([]byte, error) {
	path := os.Getenv(name)
	if path == "" {
		return nil, fmt.Errorf("%s is not set", name)
	}
	return os.ReadFile(path)
}

func setup() error {
	baseURL = os.Getenv("KEYCLOAK_ADDRESS")
	if baseURL == "" {
		baseURL = "https://localhost:8443"
	}
	var err error
	if caPEM, err = readFile("KEYCLOAK_CA_FILE"); err != nil {
		return err
	}
	pw, err := readFile("KEYCLOAK_ADMIN_PASSWORD_FILE")
	if err != nil {
		return err
	}
	adminPw = strings.TrimSpace(string(pw))
	if adminUse = os.Getenv("KEYCLOAK_ADMIN_USERNAME"); adminUse == "" {
		adminUse = "admin"
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("the CA file holds no certificate")
	}
	httpc = &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		st, _, _, err := call(http.MethodGet, baseURL+"/realms/master/.well-known/openid-configuration", "", nil)
		if err == nil && st == 200 {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("keycloak does not answer: %v (status %d)", err, st)
		}
		time.Sleep(2 * time.Second)
	}
	return createRealm()
}

// call sends one request. body is JSON, or url.Values for a form.
func call(method, u, bearer string, body any) (int, http.Header, []byte, error) {
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case url.Values:
		rd, ct = strings.NewReader(b.Encode()), "application/x-www-form-urlencoded"
	default:
		j, err := json.Marshal(b)
		if err != nil {
			return 0, nil, nil, err
		}
		rd, ct = bytes.NewReader(j), "application/json"
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, data, err
}

// admin calls the Admin REST API as the bootstrap administrator of the master
// realm, to set up what the operator's client is then tested against.
func admin(method, path string, body any) (int, http.Header, []byte, error) {
	st, _, data, err := call(http.MethodPost, baseURL+"/realms/master/protocol/openid-connect/token", "", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {adminUse}, "password": {adminPw},
	})
	if err != nil || st != 200 {
		return st, nil, nil, fmt.Errorf("master token: status %d, %v", st, err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &tok); err != nil {
		return 0, nil, nil, err
	}
	return call(method, baseURL+"/admin/realms"+path, tok.AccessToken, body)
}

// must calls admin and requires one of the statuses.
func must(method, path string, body any, want ...int) ([]byte, http.Header, error) {
	st, h, data, err := admin(method, path, body)
	if err != nil {
		return nil, nil, err
	}
	if !slices.Contains(want, st) {
		return nil, nil, fmt.Errorf("%s %s: status %d: %s", method, path, st, data)
	}
	return data, h, nil
}

// createRealm makes the realm the tests run in: a client policy that rotates
// the secret of every confidential client (the preview feature
// client-secret-rotation is on), and the operator's service account with the
// two realm-management roles its README names.
func createRealm() error {
	if _, _, err := must(http.MethodPost, "", map[string]any{"realm": realm, "enabled": true}, 201); err != nil {
		return err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	opSecret = hex.EncodeToString(raw)
	if _, _, err := must(http.MethodPost, "/"+realm+"/clients", map[string]any{
		"clientId": operatorClient, "secret": opSecret, "enabled": true, "publicClient": false,
		"serviceAccountsEnabled": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
		"clientAuthenticatorType": "client-secret",
	}, 201); err != nil {
		return err
	}
	id, err := clientUUID(operatorClient)
	if err != nil {
		return err
	}
	data, _, err := must(http.MethodGet, "/"+realm+"/clients/"+id+"/service-account-user", nil, 200)
	if err != nil {
		return err
	}
	var user struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &user); err != nil {
		return err
	}
	rm, err := clientUUID("realm-management")
	if err != nil {
		return err
	}
	var roles []json.RawMessage
	for _, name := range []string{"manage-clients", "view-clients"} {
		data, _, err := must(http.MethodGet, "/"+realm+"/clients/"+rm+"/roles/"+name, nil, 200)
		if err != nil {
			return err
		}
		roles = append(roles, data)
	}
	if _, _, err := must(http.MethodPost, "/"+realm+"/users/"+user.ID+"/role-mappings/clients/"+rm, roles, 204); err != nil {
		return err
	}
	// A client policy: every confidential client rotates its secret with the
	// overlap Keycloak's secret-rotation executor gives (a week, and two days
	// for the rotated one).
	if _, _, err := must(http.MethodPut, "/"+realm+"/client-policies/profiles", map[string]any{"profiles": []any{map[string]any{
		"name": "rotation", "executors": []any{map[string]any{
			"executor": "secret-rotation",
			"configuration": map[string]any{
				"expiration-period": 604800, "rotated-expiration-period": 172800, "remaining-rotation-period": 86400,
			},
		}},
	}}}, 204); err != nil {
		return err
	}
	_, _, err = must(http.MethodPut, "/"+realm+"/client-policies/policies", map[string]any{"policies": []any{map[string]any{
		"name": "rotate-confidential", "enabled": true,
		"conditions": []any{map[string]any{"condition": "client-access-type", "configuration": map[string]any{"type": []string{"confidential"}}}},
		"profiles":   []string{"rotation"},
	}}}, 204)
	return err
}

func clientUUID(clientID string) (string, error) {
	data, _, err := must(http.MethodGet, "/"+realm+"/clients?clientId="+url.QueryEscape(clientID), nil, 200)
	if err != nil {
		return "", err
	}
	var list []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &list); err != nil || len(list) != 1 {
		return "", fmt.Errorf("client %s: %v, %d found", clientID, err, len(list))
	}
	return list[0].ID, nil
}

func transport() idpclient.Transport {
	return idpclient.Transport{CABundle: caPEM, Dial: direct}
}

func newKeycloak(t *testing.T) *idpclient.Keycloak {
	t.Helper()
	k, err := idpclient.NewKeycloak(idpclient.KeycloakTarget{
		Transport: transport(), BaseURL: baseURL, Realm: realm, ClientID: operatorClient, ClientSecret: opSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.CloseIdleConnections)
	return k
}

// specFor is a spec with names of its own, so tests never meet.
func specFor(t *testing.T) idpclient.ClientSpec {
	t.Helper()
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	n := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "-" + hex.EncodeToString(raw)
	return idpclient.ClientSpec{
		ClientID: idpclient.KeycloakClientID("it", n), Marker: idpclient.Marker("it", n, "uid-"+hex.EncodeToString(raw)),
	}
}

// create makes the client and removes it at the end of the test.
func create(t *testing.T, k *idpclient.Keycloak, s idpclient.ClientSpec) idpclient.Client {
	t.Helper()
	c, err := k.Create(t.Context(), s)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = k.Delete(context.Background(), c.ID) })
	if !c.Matches(s) {
		t.Fatalf("a created client does not match its spec: %+v", c)
	}
	return c
}

// tokenStatus asks the realm for a client_credentials token as the client.
func tokenStatus(clientID, secret string) int {
	st, _, _, err := call(http.MethodPost, baseURL+"/realms/"+realm+"/protocol/openid-connect/token", "", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {secret},
	})
	if err != nil {
		return -1
	}
	return st
}

// realmGet makes an unauthenticated request to the realm's endpoints, which
// follows no redirect: a redirect is the answer.
func realmGet(t *testing.T, path string, q url.Values) (int, string) {
	t.Helper()
	st, h, _, err := call(http.MethodGet, baseURL+"/realms/"+realm+"/protocol/openid-connect/"+path+"?"+q.Encode(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return st, h.Get("Location")
}

func authorize(t *testing.T, clientID, redirect string, pkce bool) (int, string) {
	q := url.Values{"client_id": {clientID}, "response_type": {"code"}, "scope": {"openid"}, "redirect_uri": {redirect}, "state": {"s"}}
	if pkce {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	return realmGet(t, "auth", q)
}

func TestServiceClientWithoutRedirectURIs(t *testing.T) {
	k := newKeycloak(t)
	s := specFor(t)
	s.GrantTypes, s.Scopes = []string{"client_credentials"}, []string{"openid"}
	c := create(t, k, s)
	secret, err := k.Secret(t.Context(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st := tokenStatus(s.ClientID, secret); st != 200 {
		t.Fatalf("the client_credentials grant answers %d", st)
	}
	if st := tokenStatus(s.ClientID, secret+"x"); st != 401 {
		t.Fatalf("a wrong secret answers %d", st)
	}
	data, _, err := must(http.MethodGet, "/"+realm+"/clients/"+c.ID, nil, 200)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		RedirectURIs []string `json:"redirectUris"`
		Attributes   map[string]string
	}
	if err := json.Unmarshal(data, &rep); err != nil || len(rep.RedirectURIs) != 0 {
		t.Fatalf("redirectUris %v, %v", rep.RedirectURIs, err)
	}
	if rep.Attributes["craftainer.dev/claim"] != s.Marker {
		t.Fatalf("the marker attribute is %q", rep.Attributes["craftainer.dev/claim"])
	}
}

func TestAuthorizationCodeClient(t *testing.T) {
	k := newKeycloak(t)
	s := specFor(t)
	cb, bye := "https://app.example.org/callback", "https://app.example.org/bye"
	s.RedirectURIs, s.PostLogoutRedirectURIs, s.WebOrigins = []string{cb}, []string{bye}, []string{"https://app.example.org"}
	s.GrantTypes, s.PKCE, s.Scopes = []string{"authorization_code", "refresh_token"}, "S256", []string{"openid", "profile"}
	c := create(t, k, s)

	// The client may not use a grant it was not given.
	secret, err := k.Secret(t.Context(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st := tokenStatus(s.ClientID, secret); st == 200 {
		t.Fatal("a client without the client_credentials grant got a token")
	}

	// PKCE is required.
	if st, loc := authorize(t, s.ClientID, cb, false); st != 302 || !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("an authorization request without PKCE answers %d %q", st, loc)
	}
	if st, _ := authorize(t, s.ClientID, cb, true); st != 200 {
		t.Fatalf("an authorization request with PKCE answers %d", st)
	}
	if st, _ := authorize(t, s.ClientID, "https://evil.example.org/callback", true); st == 200 || st == 302 {
		t.Fatalf("an unregistered redirect URI answers %d", st)
	}

	// Post-logout redirects follow their own list, not the redirect URIs.
	logout := func(uri string) int {
		st, _ := realmGet(t, "logout", url.Values{"client_id": {s.ClientID}, "post_logout_redirect_uri": {uri}})
		return st
	}
	if st := logout(bye); st == 400 {
		t.Fatalf("a registered post-logout URI answers %d", st)
	}
	if st := logout(cb); st != 400 {
		t.Fatalf("a redirect URI that is not a post-logout URI answers %d", st)
	}

	// No post-logout URIs at all, and no PKCE.
	s.PostLogoutRedirectURIs, s.PKCE = nil, "Disabled"
	if err := k.Update(t.Context(), c.ID, s); err != nil {
		t.Fatal(err)
	}
	got, err := k.Get(t.Context(), c.ID, s.Marker)
	if err != nil || !got.Matches(s) {
		t.Fatalf("after the update: %v %+v", err, got)
	}
	if st := logout(bye); st != 400 {
		t.Fatalf("with no post-logout URIs, %q answers %d", bye, st)
	}
	if st := logout(cb); st != 400 {
		t.Fatalf("with no post-logout URIs, the redirect URI answers %d: Keycloak falls back to the redirect URIs", st)
	}
	if st, _ := authorize(t, s.ClientID, cb, false); st != 200 {
		t.Fatalf("with PKCE disabled, a request without it answers %d", st)
	}

	// Drift made by hand is found and repaired.
	if _, _, err := must(http.MethodPut, "/"+realm+"/clients/"+c.ID, map[string]any{
		"clientId": s.ClientID, "redirectUris": []string{cb, "https://evil.example.org/*"},
	}, 204); err != nil {
		t.Fatal(err)
	}
	if got, err = k.Get(t.Context(), c.ID, s.Marker); err != nil || got.Matches(s) {
		t.Fatalf("drift not seen: %v %+v", err, got)
	}
	if err := k.Update(t.Context(), c.ID, s); err != nil {
		t.Fatal(err)
	}
	if got, err = k.Get(t.Context(), c.ID, s.Marker); err != nil || !got.Matches(s) {
		t.Fatalf("drift not repaired: %v %+v", err, got)
	}
}

func TestPublicClient(t *testing.T) {
	k := newKeycloak(t)
	s := specFor(t)
	s.Public, s.PKCE = true, "S256"
	s.RedirectURIs, s.WebOrigins = []string{"http://localhost:3000/callback"}, []string{"http://localhost:3000"}
	c := create(t, k, s)
	if !c.Public {
		t.Fatal("the client is not public")
	}
	if _, err := k.Secret(t.Context(), c.ID); err == nil {
		t.Fatal("a public client has a secret")
	}
}

func TestScopes(t *testing.T) {
	k := newKeycloak(t)
	s := specFor(t)
	s.RedirectURIs, s.Scopes = []string{"https://app.example.org/callback"}, []string{"openid", "profile", "email"}
	c := create(t, k, s)
	names := func() []string {
		got, err := k.Get(t.Context(), c.ID, s.Marker)
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(got.Scopes)
		return got.Scopes
	}
	if got := names(); !slices.Equal(got, []string{"basic", "email", "profile"}) {
		t.Fatalf("scopes %v", got)
	}
	s.Scopes = []string{"openid"}
	if err := k.Update(t.Context(), c.ID, s); err != nil {
		t.Fatal(err)
	}
	if got := names(); !slices.Equal(got, []string{"basic"}) {
		t.Fatalf("scopes %v", got)
	}
	s.Scopes = []string{"no-such-scope"}
	if err := k.Update(t.Context(), c.ID, s); !errors.Is(err, idpclient.ErrUnknownScope) {
		t.Fatalf("%v", err)
	}
}

func TestSecretRotation(t *testing.T) {
	ctx := t.Context()
	k := newKeycloak(t)
	s := specFor(t)
	s.GrantTypes = []string{"client_credentials"}
	c := create(t, k, s)
	s0, err := k.Secret(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := k.Rotate(ctx, c.ID, s0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Secret == "" || r.Secret == s0 || !r.Overlap {
		t.Fatalf("rotation %+v: the realm's client policy should keep the old secret", r)
	}
	// Both work during the grace period.
	if st := tokenStatus(s.ClientID, s0); st != 200 {
		t.Fatalf("the previous secret answers %d during the grace period", st)
	}
	if st := tokenStatus(s.ClientID, r.Secret); st != 200 {
		t.Fatalf("the new secret answers %d", st)
	}
	// The response was lost: the same call adopts the first attempt.
	again, err := k.Rotate(ctx, c.ID, s0)
	if err != nil || again != r {
		t.Fatalf("a retried rotation: %+v, %v (first %+v)", again, err, r)
	}
	if err := k.FinishRotation(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if st := tokenStatus(s.ClientID, s0); st != 401 {
		t.Fatalf("the previous secret answers %d after the grace period", st)
	}
	if st := tokenStatus(s.ClientID, r.Secret); st != 200 {
		t.Fatalf("the new secret answers %d after the grace period", st)
	}
	if err := k.FinishRotation(ctx, c.ID); err != nil {
		t.Fatalf("finish without a rotated secret: %v", err)
	}
}

func TestOwnershipAndDeletion(t *testing.T) {
	ctx := t.Context()
	k := newKeycloak(t)
	s := specFor(t)
	s.RedirectURIs = []string{"https://app.example.org/callback"}
	c := create(t, k, s)
	// Create again: the client is there and ours.
	again, err := k.Create(ctx, s)
	if err != nil || again.ID != c.ID {
		t.Fatalf("create again: %v %+v", err, again)
	}

	// A client of the same client_id that is not ours is a name collision.
	other := specFor(t)
	if _, _, err := must(http.MethodPost, "/"+realm+"/clients", map[string]any{"clientId": other.ClientID}, 201); err != nil {
		t.Fatal(err)
	}
	id, err := clientUUID(other.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _, _, _ = admin(http.MethodDelete, "/"+realm+"/clients/"+id, nil) })
	if _, err := k.Create(ctx, other); !errors.Is(err, idpclient.ErrNameCollision) {
		t.Fatalf("create over a client that is not ours: %v", err)
	}
	if _, err := k.Get(ctx, id, other.Marker); !errors.Is(err, idpclient.ErrNameCollision) {
		t.Fatalf("get of a client that is not ours: %v", err)
	}
	if err := k.Update(ctx, id, other); !errors.Is(err, idpclient.ErrNameCollision) {
		t.Fatalf("update of a client that is not ours: %v", err)
	}

	if err := k.Delete(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Get(ctx, c.ID, s.Marker); !errors.Is(err, idpclient.ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	if err := k.Delete(ctx, c.ID); err != nil {
		t.Fatalf("delete of a deleted client: %v", err)
	}
}

func TestTLSIsVerifiedAndFailuresAreCategories(t *testing.T) {
	ctx := t.Context()
	target := func(edit func(*idpclient.KeycloakTarget)) error {
		kt := idpclient.KeycloakTarget{Transport: transport(), BaseURL: baseURL, Realm: realm, ClientID: operatorClient, ClientSecret: opSecret}
		edit(&kt)
		k, err := idpclient.NewKeycloak(kt)
		if err != nil {
			return err
		}
		defer k.CloseIdleConnections()
		return k.Probe(ctx)
	}
	if err := target(func(*idpclient.KeycloakTarget) {}); err != nil {
		t.Fatalf("the good target: %v", err)
	}
	if err := target(func(kt *idpclient.KeycloakTarget) { kt.MinTLS = tls.VersionTLS13 }); err != nil {
		t.Fatalf("TLS 1.3: %v", err)
	}
	for name, tc := range map[string]struct {
		edit func(*idpclient.KeycloakTarget)
		want error
	}{
		"an untrusted CA":  {func(kt *idpclient.KeycloakTarget) { kt.CABundle = nil }, idpclient.ErrConnTLS},
		"a wrong name":     {func(kt *idpclient.KeycloakTarget) { kt.ServerName = "wrong.example.org" }, idpclient.ErrConnTLS},
		"a wrong secret":   {func(kt *idpclient.KeycloakTarget) { kt.ClientSecret = "wrong" }, idpclient.ErrConnAuth},
		"a missing realm":  {func(kt *idpclient.KeycloakTarget) { kt.Realm = "no-such-realm" }, idpclient.ErrNotFound},
		"the plain scheme": {func(kt *idpclient.KeycloakTarget) { kt.BaseURL = strings.Replace(baseURL, "https://", "http://", 1) }, idpclient.ErrInvalidEndpoint},
		"the egress policy": {func(kt *idpclient.KeycloakTarget) {
			d, err := egress.NewPolicy(egress.ModeStrict).HostDialer(nil)
			if err != nil {
				t.Fatal(err)
			}
			kt.Dial = d
		}, idpclient.ErrConnPolicy},
	} {
		err := target(tc.edit)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
		if err != nil && (strings.Contains(err.Error(), "localhost") || strings.Contains(err.Error(), opSecret)) {
			t.Errorf("%s: the error echoes the address or a secret: %v", name, err)
		}
	}
	// A client that is unreachable is lifecycle.ErrUnreachable, never a bare error.
	if err := target(func(kt *idpclient.KeycloakTarget) { kt.CABundle = nil }); !errors.Is(err, lifecycle.ErrUnreachable) {
		t.Errorf("%v", err)
	}
}

// TestDynamicRegistration runs RFC 7591 and RFC 7592 against Keycloak's
// OpenID Connect registration endpoint, which Keycloak documents as compliant.
func TestDynamicRegistration(t *testing.T) {
	ctx := t.Context()
	data, _, err := must(http.MethodPost, "/"+realm+"/clients-initial-access", map[string]any{"count": 20, "expiration": 3600}, 200, 201)
	if err != nil {
		t.Fatal(err)
	}
	var iat struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &iat); err != nil || iat.Token == "" {
		t.Fatalf("initial access token: %v", err)
	}
	d, err := idpclient.NewDCR(idpclient.DCRTarget{
		Transport:            transport(),
		RegistrationEndpoint: baseURL + "/realms/" + realm + "/clients-registrations/openid-connect",
		InitialAccessToken:   iat.Token,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.CloseIdleConnections)

	reg := idpclient.Registration{
		ClientName: idpclient.DCRClientName("it", "dcr"), RedirectURIs: []string{"https://app.example.org/callback"},
		PostLogoutRedirectURIs: []string{"https://app.example.org/bye"}, GrantTypes: []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_basic", Scopes: []string{"profile"},
	}
	info, err := d.Register(ctx, reg)
	if err != nil {
		t.Fatal(err)
	}
	st := info.State
	t.Cleanup(func() { _ = d.Delete(context.Background(), st) })
	if st.ClientID == "" || st.RegistrationAccessToken == "" || info.Secret == "" {
		t.Fatalf("registered %+v", info)
	}
	if !strings.HasPrefix(st.RegistrationClientURI, baseURL+"/") {
		t.Fatal("the management URI is not on the endpoint's origin")
	}

	got, err := d.Get(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("read: the provider's copy satisfies the registration: %v (%+v)", got.Registration.Satisfies(reg), got.Registration)
	if got.State.ClientID != st.ClientID {
		t.Fatalf("read about %q", got.State.ClientID)
	}
	st = got.State

	reg.RedirectURIs = []string{"https://app.example.org/callback", "https://app.example.org/second"}
	upd, err := d.Update(ctx, st, reg)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("update issued a new registration access token: %v, a new secret: %v", upd.State.RegistrationAccessToken != st.RegistrationAccessToken, upd.Secret != "")
	st = upd.State
	if got, err = d.Get(ctx, st); err != nil || !slices.Contains(got.Registration.RedirectURIs, "https://app.example.org/second") {
		t.Fatalf("read after the update: %v %+v", err, got.Registration)
	}

	// Rotation is a new registration and the old one's deletion.
	second, err := d.Register(ctx, reg)
	if err != nil || second.State.ClientID == st.ClientID {
		t.Fatalf("second registration: %v %+v", err, second)
	}
	t.Cleanup(func() { _ = d.Delete(context.Background(), second.State) })
	if err := d.Delete(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get(ctx, st); !errors.Is(err, idpclient.ErrRegistrationLost) {
		t.Fatalf("read of a deleted registration: %v", err)
	}
	if err := d.Delete(ctx, st); err != nil && !errors.Is(err, idpclient.ErrRegistrationLost) {
		t.Fatalf("delete of a deleted registration: %v", err)
	}

	// A wrong initial access token is an authentication failure.
	bad, err := idpclient.NewDCR(idpclient.DCRTarget{
		Transport: transport(), RegistrationEndpoint: baseURL + "/realms/" + realm + "/clients-registrations/openid-connect",
		InitialAccessToken: "wrong",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Register(ctx, reg); !errors.Is(err, idpclient.ErrConnAuth) {
		t.Fatalf("a wrong initial access token: %v", err)
	}
}
