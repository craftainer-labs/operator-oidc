package idpclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/craftainer-labs/lib-operator-go/pkg/dcr"
)

// fakeDCR is a provider with RFC 7591 registration and RFC 7592 management.
type fakeDCR struct {
	recorder
	// iat is the initial access token a registration needs; empty needs none.
	iat string
	// rotateRAT makes an update issue a new registration access token, and
	// reissue a new client secret.
	rotateRAT, reissue bool
	// echoRAT makes a read repeat the registration access token.
	echoRAT bool
	// expires is client_secret_expires_at.
	expires int64
	// status is the status of a registration; 201 when zero.
	status int
	// mutate edits every answer before it is sent.
	mutate  func(map[string]any)
	base    string
	seq     int
	clients map[string]*dcrClient
}

type dcrClient struct {
	meta        map[string]any
	rat, secret string
	updates     int
}

func newFakeDCR() *fakeDCR { return &fakeDCR{clients: map[string]*dcrClient{}} }

func (f *fakeDCR) answer(status int, id string, c *dcrClient, rat, secret bool) reply {
	m := map[string]any{}
	for k, v := range c.meta {
		m[k] = v
	}
	m["client_id"] = id
	m["registration_client_uri"] = f.base + "/register/" + id
	if rat {
		m["registration_access_token"] = c.rat
	}
	if secret {
		m["client_secret"], m["client_secret_expires_at"] = c.secret, f.expires
	}
	if f.mutate != nil {
		f.mutate(m)
	}
	return jsonReply(status, m)
}

// seed registers a client without the client and returns its state.
func (f *fakeDCR) seed() dcr.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := "dcr-" + strconv.Itoa(f.seq)
	f.clients[id] = &dcrClient{meta: map[string]any{"client_name": "seeded"}, rat: "rat-" + strconv.Itoa(f.seq), secret: "secret-" + strconv.Itoa(f.seq)}
	return dcr.State{ClientID: id, RegistrationClientURI: f.base + "/register/" + id, RegistrationAccessToken: f.clients[id].rat}
}

func (f *fakeDCR) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rp, ok := f.forced(r)
	if !ok {
		rp = f.route(r)
	}
	rp.write(w)
}

func (f *fakeDCR) route(r *http.Request) reply {
	if r.URL.Path == "/register" {
		if f.iat != "" && r.Header.Get("Authorization") != "Bearer "+f.iat {
			return reply{status: 401, body: `{"error":"invalid_token"}`}
		}
		var meta map[string]any
		_ = json.NewDecoder(r.Body).Decode(&meta)
		f.seq++
		n := strconv.Itoa(f.seq)
		c := &dcrClient{meta: meta, rat: "rat-" + n, secret: "secret-" + n}
		f.clients["dcr-"+n] = c
		status := f.status
		if status == 0 {
			status = 201
		}
		return f.answer(status, "dcr-"+n, c, true, true)
	}
	id := strings.TrimPrefix(r.URL.Path, "/register/")
	c, ok := f.clients[id]
	if !ok || r.Header.Get("Authorization") != "Bearer "+c.rat {
		return reply{status: 401, body: `{"error":"invalid_token"}`}
	}
	switch r.Method {
	case http.MethodGet:
		return f.answer(200, id, c, f.echoRAT, false)
	case http.MethodPut:
		var meta map[string]any
		_ = json.NewDecoder(r.Body).Decode(&meta)
		if meta["client_id"] != id {
			return reply{status: 400, body: `{"error":"invalid_client_metadata"}`}
		}
		c.meta = meta
		c.updates++
		if f.rotateRAT {
			c.rat = "rat-" + id + "-" + strconv.Itoa(c.updates)
		}
		if f.reissue {
			c.secret = "secret-" + id + "-" + strconv.Itoa(c.updates)
		}
		return f.answer(200, id, c, true, f.reissue)
	}
	delete(f.clients, id)
	return reply{status: 204}
}

func newDCRFor(t *testing.T, f *fakeDCR, iat string) *DCR {
	t.Helper()
	srv, tr := startTLS(t, f)
	f.base = srv.URL
	d, err := NewDCR(DCRTarget{Transport: tr, RegistrationEndpoint: srv.URL + "/register", InitialAccessToken: iat})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func regSpec() Registration {
	return Registration{
		ClientName:   "team-a-app-abcdefghijklmnop",
		RedirectURIs: []string{"https://app.example.org/callback"}, PostLogoutRedirectURIs: []string{"https://app.example.org/bye"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_basic", Scopes: []string{"openid", "profile"},
	}
}

func TestDCRLifecycle(t *testing.T) {
	ctx := t.Context()
	f := newFakeDCR()
	f.iat, f.rotateRAT, f.expires = "iat-1", true, 1893456000
	d := newDCRFor(t, f, "iat-1")
	reg := regSpec()

	info, err := d.Register(ctx, reg)
	if err != nil {
		t.Fatal(err)
	}
	want := dcr.State{ClientID: "dcr-1", RegistrationClientURI: f.base + "/register/dcr-1", RegistrationAccessToken: "rat-1"}
	if info.State != want || info.Secret != "secret-1" || !info.SecretExpiresAt.Equal(time.Unix(1893456000, 0)) {
		t.Fatalf("registered %+v", info)
	}
	if !info.Registration.Satisfies(reg) {
		t.Fatalf("the provider's copy %+v is not the registration", info.Registration)
	}
	sent := f.body("POST /register")
	if _, ok := sent["client_id"]; ok || sent["scope"] != "openid profile" || f.auth["POST /register"] != "Bearer iat-1" ||
		sent["client_name"] != reg.ClientName || sent["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Fatalf("sent %v", sent)
	}
	if rt, _ := sent["response_types"].([]any); len(rt) != 1 || rt[0] != "code" {
		t.Fatalf("response_types %v", sent["response_types"])
	}

	// A read answers neither a token nor a secret: the state is kept.
	got, err := d.Get(ctx, info.State)
	if err != nil || got.State != info.State || got.Secret != "" || !got.SecretExpiresAt.IsZero() || !got.Registration.Satisfies(reg) {
		t.Fatalf("read %+v, %v", got, err)
	}
	f.echoRAT = true
	if got, err = d.Get(ctx, info.State); err != nil || got.State != info.State {
		t.Fatalf("read with the token echoed %+v, %v", got, err)
	}

	// An update sends the client_id and no token, with the token of the
	// registration, and the provider issues a new one.
	reg2 := reg
	reg2.RedirectURIs = []string{"https://app.example.org/callback", "https://app.example.org/other"}
	upd, err := d.Update(ctx, info.State, reg2)
	if err != nil {
		t.Fatal(err)
	}
	put := f.body("PUT /register/dcr-1")
	if put["client_id"] != "dcr-1" || put["registration_access_token"] != nil || put["client_secret"] != nil ||
		f.auth["PUT /register/dcr-1"] != "Bearer rat-1" {
		t.Fatalf("sent %v", put)
	}
	if upd.State.RegistrationAccessToken != "rat-dcr-1-1" || upd.State.ClientID != "dcr-1" || upd.Secret != "" {
		t.Fatalf("updated %+v", upd)
	}
	if _, err := d.Get(ctx, info.State); !errors.Is(err, ErrRegistrationLost) {
		t.Fatalf("the old token still reads: %v", err)
	}
	if got, err = d.Get(ctx, upd.State); err != nil || !got.Registration.Satisfies(reg2) || got.Registration.Satisfies(reg) {
		t.Fatalf("read after the update %+v, %v", got, err)
	}

	// A new secret in the answer to an update comes back.
	f.reissue = true
	upd, err = d.Update(ctx, upd.State, reg2)
	if err != nil || upd.Secret != "secret-dcr-1-2" || upd.SecretExpiresAt.IsZero() {
		t.Fatalf("updated %+v, %v", upd, err)
	}

	if err := d.Delete(ctx, upd.State); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(ctx, upd.State); !errors.Is(err, ErrRegistrationLost) {
		// The fake answers 401 for a client it does not know.
		t.Fatalf("delete of a deleted client: %v", err)
	}
	d.CloseIdleConnections()
}

func TestDCRRegisterVariants(t *testing.T) {
	ctx := t.Context()
	// An anonymous registration, answered 200, of a public client.
	f := newFakeDCR()
	f.status = 200
	f.mutate = func(m map[string]any) { delete(m, "client_secret"); delete(m, "client_secret_expires_at") }
	d := newDCRFor(t, f, "")
	reg := Registration{ClientName: "spa", RedirectURIs: []string{"https://a.example.org/"}, GrantTypes: []string{"authorization_code"}, TokenEndpointAuthMethod: "none"}
	info, err := d.Register(ctx, reg)
	if err != nil || info.Secret != "" || info.State.ClientID != "dcr-1" {
		t.Fatalf("%+v, %v", info, err)
	}
	if _, ok := f.auth["POST /register"]; !ok || f.auth["POST /register"] != "" {
		t.Fatalf("a bearer was sent without an initial access token: %q", f.auth["POST /register"])
	}

	// A client_credentials-only client has no redirect URIs and no response types.
	cc := Registration{ClientName: "svc", GrantTypes: []string{"client_credentials"}, TokenEndpointAuthMethod: "client_secret_post"}
	if _, err := d.Register(ctx, cc); err != nil {
		t.Fatal(err)
	}
	sent := f.body("POST /register")
	if _, ok := sent["redirect_uris"]; ok {
		t.Fatalf("redirect_uris of a client without any: %v", sent)
	}
	if rt, ok := sent["response_types"].([]any); !ok || len(rt) != 0 {
		t.Fatalf("response_types %#v, want []", sent["response_types"])
	}
}

func TestDCRBadAnswers(t *testing.T) {
	ctx := t.Context()
	other := func(uri string) func(map[string]any) {
		return func(m map[string]any) { m["registration_client_uri"] = uri }
	}
	for name, mutate := range map[string]func(map[string]any){
		"another host": other("https://other.example.org/register/x"),
		"another port": other("https://127.0.0.1:1/register/x"),
		"http": func(m map[string]any) {
			m["registration_client_uri"] = strings.Replace(m["registration_client_uri"].(string), "https://", "http://", 1)
		},
		"userinfo": func(m map[string]any) {
			m["registration_client_uri"] = strings.Replace(m["registration_client_uri"].(string), "https://", "https://u:p@", 1)
		},
		"no URI":            func(m map[string]any) { delete(m, "registration_client_uri") },
		"no token":          func(m map[string]any) { delete(m, "registration_access_token") },
		"no client id":      func(m map[string]any) { delete(m, "client_id") },
		"redirect_uris int": func(m map[string]any) { m["redirect_uris"] = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeDCR()
			f.mutate = mutate
			_, err := newDCRFor(t, f, "").Register(ctx, regSpec())
			if !errors.Is(err, ErrBadResponse) {
				t.Fatalf("%v", err)
			}
			if strings.Contains(err.Error(), "example.org") || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("the error echoes the answer: %v", err)
			}
		})
	}

	t.Run("not JSON", func(t *testing.T) {
		f := newFakeDCR()
		f.rules = []rule{{"POST", "/register", reply{status: 201, body: "<html>"}}}
		if _, err := newDCRFor(t, f, "").Register(ctx, regSpec()); !errors.Is(err, ErrBadResponse) {
			t.Fatalf("%v", err)
		}
	})

	t.Run("a read about another client", func(t *testing.T) {
		f := newFakeDCR()
		d := newDCRFor(t, f, "")
		st := f.seed()
		f.mutate = func(m map[string]any) { m["client_id"] = "dcr-9" }
		if _, err := d.Get(ctx, st); !errors.Is(err, ErrBadResponse) {
			t.Fatalf("%v", err)
		}
	})
}

func TestDCRRefusals(t *testing.T) {
	ctx := t.Context()
	f := newFakeDCR()
	d := newDCRFor(t, f, "")
	st := f.seed()
	reg := regSpec()

	// The registration access token is never sent where the provider did not
	// say the client lives.
	for name, bad := range map[string]dcr.State{
		"empty":       {},
		"no client":   {RegistrationClientURI: st.RegistrationClientURI, RegistrationAccessToken: "t"},
		"no token":    {ClientID: "x", RegistrationClientURI: st.RegistrationClientURI},
		"other host":  {ClientID: "x", RegistrationClientURI: "https://other.example.org/register/x", RegistrationAccessToken: "t"},
		"http":        {ClientID: "x", RegistrationClientURI: strings.Replace(st.RegistrationClientURI, "https://", "http://", 1), RegistrationAccessToken: "t"},
		"unparseable": {ClientID: "x", RegistrationClientURI: "https://%zz", RegistrationAccessToken: "t"},
	} {
		if _, err := d.Get(ctx, bad); !errors.Is(err, ErrInvalidState) {
			t.Errorf("get %s: %v", name, err)
		}
		if _, err := d.Update(ctx, bad, reg); !errors.Is(err, ErrInvalidState) {
			t.Errorf("update %s: %v", name, err)
		}
		if err := d.Delete(ctx, bad); !errors.Is(err, ErrInvalidState) {
			t.Errorf("delete %s: %v", name, err)
		}
	}
	if f.count() != 0 {
		t.Fatalf("%d requests were sent for an invalid state", f.count())
	}

	for _, status := range []int{401, 403, 404} {
		f.rules = []rule{{"GET", st.ClientID, reply{status: status}}, {"PUT", st.ClientID, reply{status: status}}, {"DELETE", st.ClientID, reply{status: status}}}
		if _, err := d.Get(ctx, st); !errors.Is(err, ErrRegistrationLost) {
			t.Errorf("get %d: %v", status, err)
		}
		if _, err := d.Update(ctx, st, reg); !errors.Is(err, ErrRegistrationLost) {
			t.Errorf("update %d: %v", status, err)
		}
		err := d.Delete(ctx, st)
		if (status == 404) != (err == nil) || (status != 404 && !errors.Is(err, ErrRegistrationLost)) {
			t.Errorf("delete %d: %v", status, err)
		}
	}
	f.rules = []rule{
		{"GET", st.ClientID, reply{status: 500, body: "boom https://10.0.0.1"}}, {"PUT", st.ClientID, reply{status: 500}},
		{"DELETE", st.ClientID, reply{status: 500}},
	}
	if _, err := d.Get(ctx, st); statusOf(err) != 500 || strings.Contains(err.Error(), "10.0.0.1") {
		t.Errorf("get: %v", err)
	}
	if _, err := d.Update(ctx, st, reg); statusOf(err) != 500 {
		t.Errorf("update: %v", err)
	}
	if err := d.Delete(ctx, st); statusOf(err) != 500 {
		t.Errorf("delete: %v", err)
	}
	f.rules = []rule{{"GET", st.ClientID, reply{status: 200, body: "<html>"}}, {"PUT", st.ClientID, reply{status: 200, body: "<html>"}}, {"DELETE", st.ClientID, reply{status: 200}}}
	if _, err := d.Get(ctx, st); !errors.Is(err, ErrBadResponse) {
		t.Errorf("get: %v", err)
	}
	if _, err := d.Update(ctx, st, reg); !errors.Is(err, ErrBadResponse) {
		t.Errorf("update: %v", err)
	}
	if err := d.Delete(ctx, st); err != nil {
		t.Errorf("delete answered 200: %v", err)
	}
}

func TestDCRRegisterRefusals(t *testing.T) {
	ctx := t.Context()
	f := newFakeDCR()
	f.iat = "right"
	// A wrong initial access token is an authentication failure of the
	// provider, with a fixed text.
	_, err := newDCRFor(t, f, "wrong").Register(ctx, regSpec())
	if !errors.Is(err, ErrConnAuth) || strings.Contains(err.Error(), "wrong") || strings.Contains(err.Error(), "invalid_token") {
		t.Fatalf("%v", err)
	}
	f.rules = []rule{{"POST", "/register", reply{status: 400, body: `{"error":"invalid_redirect_uri","error_description":"https://10.0.0.1"}`}}}
	_, err = newDCRFor(t, f, "right").Register(ctx, regSpec())
	if statusOf(err) != 400 || strings.Contains(err.Error(), "10.0.0.1") {
		t.Fatalf("%v", err)
	}
	f.rules = nil
	f.failAt, f.failWith = f.count()+1, reply{status: 500}
	if _, err = newDCRFor(t, f, "right").Register(ctx, regSpec()); statusOf(err) != 500 {
		t.Fatalf("%v", err)
	}
}

func TestNewDCR(t *testing.T) {
	good := DCRTarget{Transport: Transport{Dial: direct}, RegistrationEndpoint: "https://idp.example.org/register"}
	if _, err := NewDCR(good); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		edit func(*DCRTarget)
		want error
	}{
		"http":     {func(t *DCRTarget) { t.RegistrationEndpoint = "http://idp.example.org/register" }, ErrInvalidEndpoint},
		"userinfo": {func(t *DCRTarget) { t.RegistrationEndpoint = "https://u:p@idp.example.org/register" }, ErrInvalidEndpoint},
		"query":    {func(t *DCRTarget) { t.RegistrationEndpoint = "https://idp.example.org/register?x=1" }, ErrInvalidEndpoint},
		"no dial":  {func(t *DCRTarget) { t.Dial = nil }, ErrNoDialer},
		"bad CA":   {func(t *DCRTarget) { t.CABundle = []byte("x") }, ErrInvalidCA},
	} {
		target := good
		tc.edit(&target)
		if _, err := NewDCR(target); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"https://idp.example.org/a", "https://IDP.example.org:443/b?x=1", true},
		{"https://idp.example.org:8443/a", "https://idp.example.org:8443/b", true},
		{"https://idp.example.org/a", "https://idp.example.org:8443/b", false},
		{"https://idp.example.org/a", "https://idp2.example.org/b", false},
		{"https://idp.example.org/a", "http://idp.example.org/b", false},
	} {
		if got := sameOrigin(u(tc.a), u(tc.b)); got != tc.want {
			t.Errorf("%s %s: %v", tc.a, tc.b, got)
		}
	}
}

func TestRegistrationSatisfies(t *testing.T) {
	want := regSpec()
	if !(Registration{}).Satisfies(want) {
		t.Error("a provider that echoes nothing is not in disagreement")
	}
	if !want.Satisfies(want) {
		t.Error("the same registration differs")
	}
	for name, edit := range map[string]func(*Registration){
		"name":         func(r *Registration) { r.ClientName = "x" },
		"auth method":  func(r *Registration) { r.TokenEndpointAuthMethod = "none" },
		"redirects":    func(r *Registration) { r.RedirectURIs = []string{"https://evil.example.org/"} },
		"post logout":  func(r *Registration) { r.PostLogoutRedirectURIs = []string{"https://evil.example.org/"} },
		"grants":       func(r *Registration) { r.GrantTypes = []string{"client_credentials"} },
		"scopes":       func(r *Registration) { r.Scopes = []string{"openid", "admin"} },
		"fewer scopes": func(r *Registration) { r.Scopes = []string{"openid"} },
	} {
		got := regSpec()
		edit(&got)
		if got.Satisfies(want) {
			t.Errorf("%s: satisfied", name)
		}
	}
	// What the provider defaults stands where the spec says nothing.
	bare := Registration{ClientName: want.ClientName, RedirectURIs: want.RedirectURIs, PostLogoutRedirectURIs: want.PostLogoutRedirectURIs}
	if !want.Satisfies(bare) {
		t.Error("a provider default is drift")
	}
	got := regSpec()
	got.Scopes = []string{"profile", "openid"}
	if !got.Satisfies(want) {
		t.Error("the order of scopes is drift")
	}
}
