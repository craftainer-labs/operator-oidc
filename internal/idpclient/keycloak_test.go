package idpclient

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
)

func spec() ClientSpec {
	return ClientSpec{
		ClientID: "team-a-app-abcdefghij", Marker: "team-a/app/uid-1",
		RedirectURIs:           []string{"https://app.example.org/callback"},
		PostLogoutRedirectURIs: []string{"https://app.example.org/bye", "https://app.example.org/out"},
		WebOrigins:             []string{"https://app.example.org"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		PKCE:                   "S256", Scopes: []string{"openid", "profile"},
	}
}

func scopeNamesOf(c Client) []string {
	out := slices.Clone(c.Scopes)
	slices.Sort(out)
	return out
}

func TestKeycloakLifecycle(t *testing.T) {
	ctx := t.Context()
	f := newFakeKeycloak()
	k := newKeycloakFor(t, f)
	s := spec()

	c, err := k.Create(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID == "" || c.ClientID != s.ClientID || c.Public {
		t.Fatalf("created %+v", c)
	}
	if !c.Matches(s) {
		t.Fatalf("a created client does not match its spec: %+v", c.rep)
	}
	// The realm's default scopes are replaced by the spec's, besides basic.
	if got := scopeNamesOf(c); !slices.Equal(got, []string{"basic", "profile"}) {
		t.Fatalf("scopes %v", got)
	}
	posted := f.body("POST " + kcAdmin + "/clients")
	if posted["standardFlowEnabled"] != true || posted["serviceAccountsEnabled"] != false ||
		posted["directAccessGrantsEnabled"] != false || posted["publicClient"] != false {
		t.Fatalf("posted %v", posted)
	}
	attrs := posted["attributes"].(map[string]any)
	if attrs[markerAttr] != s.Marker || attrs[pkceAttr] != "S256" || attrs[refreshAttr] != "true" ||
		attrs[postLogoutAttr] != "https://app.example.org/bye##https://app.example.org/out" {
		t.Fatalf("attributes %v", attrs)
	}
	secret, err := k.Secret(ctx, c.ID)
	if err != nil || secret != "secret-"+c.ID {
		t.Fatalf("secret %q, %v", secret, err)
	}

	// Drift: someone widens the redirect URIs and adds a mapper and an attribute.
	stored := f.client(c.ID)
	stored.rep["redirectUris"] = []any{"https://evil.example.org/"}
	stored.rep["protocolMappers"] = []any{"keep me"}
	stored.rep["attributes"].(map[string]any)["custom"] = "keep me too"
	c, err = k.Get(ctx, c.ID, s.Marker)
	if err != nil {
		t.Fatal(err)
	}
	if c.Matches(s) {
		t.Fatal("drifted client matches")
	}
	if err := k.Update(ctx, c.ID, s); err != nil {
		t.Fatal(err)
	}
	if c, err = k.Get(ctx, c.ID, s.Marker); err != nil || !c.Matches(s) {
		t.Fatalf("not converged: %v %+v", err, c.rep)
	}
	stored = f.client(c.ID)
	if stored.rep["protocolMappers"] == nil || stored.rep["attributes"].(map[string]any)["custom"] != "keep me too" {
		t.Fatalf("an update dropped what it does not own: %v", stored.rep)
	}

	// PKCE disabled, no refresh tokens, no post-logout URIs, another scope.
	s2 := s
	s2.PKCE, s2.GrantTypes, s2.PostLogoutRedirectURIs, s2.Scopes = "Disabled", nil, nil, []string{"openid", "email", "basic"}
	if err := k.Update(ctx, c.ID, s2); err != nil {
		t.Fatal(err)
	}
	if c, err = k.Get(ctx, c.ID, s.Marker); err != nil || !c.Matches(s2) || c.Matches(s) {
		t.Fatalf("not converged: %v %+v", err, c.rep)
	}
	if got := f.client(c.ID).rep["attributes"].(map[string]any)[pkceAttr]; got != "" {
		t.Fatalf("the PKCE attribute is %v, want it emptied", got)
	}
	if got := scopeNamesOf(c); !slices.Equal(got, []string{"basic", "email"}) {
		t.Fatalf("scopes %v", got)
	}
	if got := f.client(c.ID).rep["attributes"].(map[string]any)[postLogoutAttr]; got != "-" {
		t.Fatalf("no post-logout URIs is written as %v", got)
	}

	// Create again: the client is there already and carries the marker.
	again, err := k.Create(ctx, s)
	if err != nil || again.ID != c.ID || !again.Matches(s) {
		t.Fatalf("create again: %v %+v", err, again)
	}

	if err := k.Delete(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Get(ctx, c.ID, s.Marker); !errors.Is(err, ErrNotFound) || statusOf(err) != 404 {
		t.Fatalf("get after delete: %v", err)
	}
	if err := k.Delete(ctx, c.ID); err != nil {
		t.Fatalf("delete of a deleted client: %v", err)
	}
	k.CloseIdleConnections()
}

func TestKeycloakClientKinds(t *testing.T) {
	ctx := t.Context()
	f := newFakeKeycloak()
	k := newKeycloakFor(t, f)
	for _, tc := range []struct {
		name string
		spec ClientSpec
	}{
		// A client_credentials-only client has no redirect URIs (NO6a-x).
		{"service", ClientSpec{ClientID: "svc", Marker: "m1", GrantTypes: []string{"client_credentials"}, Scopes: []string{"openid"}}},
		{"public", ClientSpec{
			ClientID: "spa", Marker: "m2", Public: true, RedirectURIs: []string{"http://localhost:3000/cb"},
			WebOrigins: []string{"http://localhost:3000"}, PKCE: "S256",
		}},
		{"defaults", ClientSpec{ClientID: "dflt", Marker: "m3", RedirectURIs: []string{"https://a.example.org/cb"}}},
	} {
		name, s := tc.name, tc.spec
		c, err := k.Create(ctx, s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !c.Matches(s) || c.Public != s.Public {
			t.Fatalf("%s: %+v", name, c.rep)
		}
	}
	posted := f.body("POST " + kcAdmin + "/clients")
	if posted["clientId"] != "dflt" || posted["standardFlowEnabled"] != true {
		t.Fatalf("a client with no grant types is an authorization_code client: %v", posted)
	}
	for _, c := range f.clients {
		if c.rep["clientId"] == "svc" {
			if uris, ok := c.rep["redirectUris"].([]any); !ok || len(uris) != 0 {
				t.Fatalf("redirectUris of a client without any is %#v, want []", c.rep["redirectUris"])
			}
			if c.rep["serviceAccountsEnabled"] != true || c.rep["standardFlowEnabled"] != false {
				t.Fatalf("service client %v", c.rep)
			}
		}
	}
}

func TestKeycloakRefusals(t *testing.T) {
	ctx := t.Context()
	f := newFakeKeycloak()
	k := newKeycloakFor(t, f)
	s := spec()
	foreign := f.seed("taken", "someone/else/uid-9")
	mine := f.seed("mine", s.Marker)

	check := func(name string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	_, err := k.Create(ctx, ClientSpec{ClientID: "taken", Marker: s.Marker})
	check("create over another claim's client", err, ErrNameCollision)
	if f.saw("PUT "+kcAdmin+"/clients/"+foreign) != 0 {
		t.Error("the foreign client was changed")
	}
	_, err = k.Get(ctx, foreign, s.Marker)
	check("get of another claim's client", err, ErrNameCollision)
	check("update of another claim's client", k.Update(ctx, foreign, ClientSpec{ClientID: "taken", Marker: s.Marker}), ErrNameCollision)
	if f.saw("PUT "+kcAdmin+"/clients/"+foreign) != 0 {
		t.Error("the foreign client was changed by Update")
	}

	posts := f.saw("POST " + kcAdmin + "/clients")
	_, err = k.Create(ctx, ClientSpec{ClientID: "x", Marker: "m", Scopes: []string{"nope"}})
	check("unknown scope", err, ErrUnknownScope)
	if f.saw("POST "+kcAdmin+"/clients") != posts {
		t.Error("a client was created although a scope is unknown")
	}
	check("update with an unknown scope", k.Update(ctx, mine, ClientSpec{ClientID: "x", Marker: s.Marker, Scopes: []string{"nope"}}), ErrUnknownScope)

	_, err = k.Create(ctx, ClientSpec{})
	check("create without a name", err, ErrInvalidSpec)
	check("update without a name", k.Update(ctx, mine, ClientSpec{}), ErrInvalidSpec)
	_, err = k.Get(ctx, mine, "")
	check("get without a marker", err, ErrInvalidSpec)
	for _, id := range []string{"", "../admin", "a/b", "a b", strings.Repeat("a", 65), "id?x=1"} {
		_, err = k.Get(ctx, id, s.Marker)
		check("get "+id, err, ErrInvalidID)
		check("update "+id, k.Update(ctx, id, s), ErrInvalidID)
		check("delete "+id, k.Delete(ctx, id), ErrInvalidID)
		_, err = k.Secret(ctx, id)
		check("secret "+id, err, ErrInvalidID)
		_, err = k.Rotate(ctx, id, "")
		check("rotate "+id, err, ErrInvalidID)
		check("finish "+id, k.FinishRotation(ctx, id), ErrInvalidID)
	}
}

func TestKeycloakBadAnswers(t *testing.T) {
	ctx := t.Context()
	s := spec()
	for name, tc := range map[string]struct {
		rules []rule
		run   func(k *Keycloak, id string) error
		want  error
		code  int // when set, the HTTP status the error must carry
	}{
		"created without a Location": {
			rules: []rule{{"POST", "/clients", reply{status: 201}}},
			run:   func(k *Keycloak, _ string) error { _, err := k.Create(ctx, s); return err },
			want:  ErrBadResponse,
		},
		"a conflict over a client that is not listed": {
			rules: []rule{{"POST", "/clients", reply{status: 409}}, {"GET", "/clients", reply{status: 200, body: "[]"}}},
			run:   func(k *Keycloak, _ string) error { _, err := k.Create(ctx, s); return err },
			want:  ErrNotFound,
		},
		"a scope with an id that is a path": {
			rules: []rule{{"GET", "/client-scopes", reply{status: 200, body: `[{"id":"../x","name":"a"}]`}}},
			run:   func(k *Keycloak, _ string) error { _, err := k.Create(ctx, s); return err },
			want:  ErrBadResponse,
		},
		"a secret that is empty": {
			rules: []rule{{"GET", "/client-secret", reply{status: 200, body: `{"type":"secret"}`}}},
			run:   func(k *Keycloak, id string) error { _, err := k.Secret(ctx, id); return err },
			want:  ErrBadResponse,
		},
		"a rotated secret that is empty": {
			rules: []rule{{"GET", "/client-secret/rotated", reply{status: 200, body: `{}`}}},
			run:   func(k *Keycloak, id string) error { _, err := k.Rotate(ctx, id, ""); return err },
			want:  ErrBadResponse,
		},
		"a rotated secret that cannot be read": {
			rules: []rule{{"GET", "/client-secret/rotated", reply{status: 500}}},
			run:   func(k *Keycloak, id string) error { _, err := k.Rotate(ctx, id, ""); return err },
			code:  500,
		},
		"a client that is not an object": {
			rules: []rule{{"GET", "/clients/id-1", reply{status: 200, body: `[1]`}}},
			run:   func(k *Keycloak, id string) error { _, err := k.Get(ctx, id, s.Marker); return err },
			want:  ErrBadResponse,
		},
		"a refused delete": {
			rules: []rule{{"DELETE", "/clients/id-1", reply{status: 500, body: "internal https://10.0.0.1/secret"}}},
			run:   func(k *Keycloak, id string) error { return k.Delete(ctx, id) },
			code:  500,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeKeycloak()
			f.rotation = true
			id := f.seed(s.ClientID, s.Marker)
			f.rules = tc.rules
			err := tc.run(newKeycloakFor(t, f), id)
			if tc.code != 0 {
				if statusOf(err) != tc.code {
					t.Fatalf("%v, want status %d", err, tc.code)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
			for _, leak := range []string{"10.0.0.1", "internal", "127.0.0.1"} {
				if err != nil && strings.Contains(err.Error(), leak) {
					t.Fatalf("the error leaks %q: %v", leak, err)
				}
			}
		})
	}
}

func TestKeycloakRotation(t *testing.T) {
	ctx := t.Context()
	for _, overlap := range []bool{true, false} {
		f := newFakeKeycloak()
		f.rotation = overlap
		k := newKeycloakFor(t, f)
		c, err := k.Create(ctx, spec())
		if err != nil {
			t.Fatal(err)
		}
		before, _ := k.Secret(ctx, c.ID)
		r, err := k.Rotate(ctx, c.ID, before)
		if err != nil || r.Secret == "" || r.Secret == before || r.Overlap != overlap {
			t.Fatalf("overlap=%v: %+v, %v", overlap, r, err)
		}
		// The response was lost and the controller tries again with the
		// secret it still holds: the first attempt's result is adopted, and
		// Keycloak's one rotated secret still is the one consumers hold.
		retry, err := k.Rotate(ctx, c.ID, before)
		if err != nil || retry != r || f.client(c.ID).regens != 1 {
			t.Fatalf("retry: %+v, %v, %d regenerations", retry, err, f.client(c.ID).regens)
		}
		if overlap {
			if f.client(c.ID).rotated != before {
				t.Fatal("the previous secret is not the rotated one")
			}
		}
		if err := k.FinishRotation(ctx, c.ID); err != nil {
			t.Fatal(err)
		}
		if f.client(c.ID).rotated != "" {
			t.Fatal("the rotated secret stayed")
		}
		if err := k.FinishRotation(ctx, c.ID); err != nil {
			t.Fatalf("finish without a rotated secret: %v", err)
		}
		// No secret to compare with: always rotates.
		if r, err = k.Rotate(ctx, c.ID, ""); err != nil || f.client(c.ID).regens != 2 || r.Secret == retry.Secret {
			t.Fatalf("%+v, %v, %d regenerations", r, err, f.client(c.ID).regens)
		}
	}
}

func TestKeycloakToken(t *testing.T) {
	ctx := t.Context()
	f := newFakeKeycloak()
	k := newKeycloakFor(t, f)
	now := time.Now()
	k.now = func() time.Time { return now }

	for range 3 {
		if err := k.Probe(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokens != 1 {
		t.Fatalf("%d tokens for three requests", f.tokens)
	}
	if got := f.auth["GET "+kcAdmin+"/clients"]; got != "Bearer token-1" {
		t.Fatalf("authorization %q", got)
	}
	now = now.Add(time.Minute)
	if err := k.Probe(ctx); err != nil || f.tokens != 2 {
		t.Fatalf("an expired token is not renewed: %v, %d", err, f.tokens)
	}

	// An admin request the provider answers 401 drops the token.
	f.rules = []rule{{"GET", "/clients", reply{status: 401}}}
	if err := k.Probe(ctx); !errors.Is(err, ErrConnAuth) || !errors.Is(err, lifecycle.ErrUnreachable) {
		t.Fatalf("probe: %v", err)
	}
	f.rules = nil
	if err := k.Probe(ctx); err != nil || f.tokens != 3 {
		t.Fatalf("after a 401: %v, %d tokens", err, f.tokens)
	}
}

func TestKeycloakTokenFailures(t *testing.T) {
	ctx := t.Context()
	for name, tc := range map[string]struct {
		rule reply
		want func(error) bool
	}{
		"invalid_client": {reply{status: 401, body: `{"error":"invalid_client"}`}, func(err error) bool { return errors.Is(err, ErrConnAuth) }},
		"unauthorized_client": {
			reply{status: 400, body: `{"error":"unauthorized_client"}`},
			func(err error) bool { return errors.Is(err, ErrConnAuth) },
		},
		"server error": {reply{status: 500}, func(err error) bool { return statusOf(err) == 500 }},
		"not JSON":     {reply{status: 200, body: "<html>"}, func(err error) bool { return errors.Is(err, ErrBadResponse) }},
		"no token":     {reply{status: 200, body: `{"expires_in":60}`}, func(err error) bool { return errors.Is(err, ErrBadResponse) }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeKeycloak()
			f.rules = []rule{{"POST", "/token", tc.rule}}
			err := newKeycloakFor(t, f).Probe(ctx)
			if !tc.want(err) {
				t.Fatalf("%v", err)
			}
			if f.saw("GET "+kcAdmin+"/clients") != 0 {
				t.Fatal("an admin request was sent without a token")
			}
		})
	}

	// The fake rejects other credentials and echoes the secret in its body.
	f := newFakeKeycloak()
	srv, tr := startTLS(t, f)
	k, err := NewKeycloak(KeycloakTarget{Transport: tr, BaseURL: srv.URL, Realm: "test", ClientID: "operator", ClientSecret: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	err = k.Probe(ctx)
	if !errors.Is(err, ErrConnAuth) {
		t.Fatalf("%v", err)
	}
	for _, leak := range []string{"wrong", "operator", "invalid_client", srv.URL, "127.0.0.1"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the error leaks %q: %v", leak, err)
		}
	}
}

func TestNewKeycloak(t *testing.T) {
	good := KeycloakTarget{
		Transport: Transport{Dial: direct}, BaseURL: "https://kc.example.org/auth", Realm: "my.realm_1-x",
		ClientID: "operator", ClientSecret: "s",
	}
	k, err := NewKeycloak(good)
	if err != nil {
		t.Fatal(err)
	}
	if got := k.admin("clients").String(); got != "https://kc.example.org/auth/admin/realms/my.realm_1-x/clients" {
		t.Fatalf("admin URL %s", got)
	}
	for name, mod := range map[string]struct {
		edit func(*KeycloakTarget)
		want error
	}{
		"http":          {func(t *KeycloakTarget) { t.BaseURL = "http://kc.example.org" }, ErrInvalidEndpoint},
		"no host":       {func(t *KeycloakTarget) { t.BaseURL = "https:///x" }, ErrInvalidEndpoint},
		"userinfo":      {func(t *KeycloakTarget) { t.BaseURL = "https://u:p@kc.example.org" }, ErrInvalidEndpoint},
		"query":         {func(t *KeycloakTarget) { t.BaseURL = "https://kc.example.org?a=b" }, ErrInvalidEndpoint},
		"empty query":   {func(t *KeycloakTarget) { t.BaseURL = "https://kc.example.org?" }, ErrInvalidEndpoint},
		"fragment":      {func(t *KeycloakTarget) { t.BaseURL = "https://kc.example.org#x" }, ErrInvalidEndpoint},
		"unparsable":    {func(t *KeycloakTarget) { t.BaseURL = "https://kc.example.org/%zz" }, ErrInvalidEndpoint},
		"dot realm":     {func(t *KeycloakTarget) { t.Realm = "." }, ErrInvalidRealm},
		"dotdot realm":  {func(t *KeycloakTarget) { t.Realm = ".." }, ErrInvalidRealm},
		"slash realm":   {func(t *KeycloakTarget) { t.Realm = "a/b" }, ErrInvalidRealm},
		"empty realm":   {func(t *KeycloakTarget) { t.Realm = "" }, ErrInvalidRealm},
		"no client id":  {func(t *KeycloakTarget) { t.ClientID = "" }, ErrNoCredentials},
		"no secret":     {func(t *KeycloakTarget) { t.ClientSecret = "" }, ErrNoCredentials},
		"no dialer":     {func(t *KeycloakTarget) { t.Dial = nil }, ErrNoDialer},
		"bad CA bundle": {func(t *KeycloakTarget) { t.CABundle = []byte("not PEM") }, ErrInvalidCA},
	} {
		target := good
		mod.edit(&target)
		if _, err := NewKeycloak(target); !errors.Is(err, mod.want) {
			t.Errorf("%s: %v, want %v", name, err, mod.want)
		} else if strings.Contains(err.Error(), "kc.example.org") || strings.Contains(err.Error(), "u:p") {
			t.Errorf("%s: the error echoes the URL: %v", name, err)
		}
	}
}

func TestClientMatches(t *testing.T) {
	ctx := t.Context()
	s := spec()
	k := newKeycloakFor(t, newFakeKeycloak())
	c, err := k.Create(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	clone := func() Client {
		d := c
		d.rep.RedirectURIs = slices.Clone(c.rep.RedirectURIs)
		d.rep.WebOrigins = slices.Clone(c.rep.WebOrigins)
		d.rep.Attributes = maps.Clone(c.rep.Attributes)
		d.Scopes = slices.Clone(c.Scopes)
		return d
	}
	if !clone().Matches(s) {
		t.Fatal("the base case does not match")
	}
	for name, edit := range map[string]func(*Client){
		"renamed":          func(c *Client) { c.rep.ClientID = "other" },
		"disabled":         func(c *Client) { c.rep.Enabled = false },
		"bearer only":      func(c *Client) { c.rep.BearerOnly = true },
		"implicit flow":    func(c *Client) { c.rep.ImplicitFlowEnabled = true },
		"direct grants":    func(c *Client) { c.rep.DirectAccessGrantsEnabled = true },
		"public":           func(c *Client) { c.rep.PublicClient = true },
		"no standard flow": func(c *Client) { c.rep.StandardFlowEnabled = false },
		"service account":  func(c *Client) { c.rep.ServiceAccountsEnabled = true },
		"redirect":         func(c *Client) { c.rep.RedirectURIs = append(c.rep.RedirectURIs, "https://x.example.org/") },
		"origins":          func(c *Client) { c.rep.WebOrigins = nil },
		"post logout":      func(c *Client) { c.rep.Attributes[postLogoutAttr] = "https://x.example.org/" },
		"pkce":             func(c *Client) { delete(c.rep.Attributes, pkceAttr) },
		"refresh":          func(c *Client) { c.rep.Attributes[refreshAttr] = "false" },
		"scope":            func(c *Client) { c.Scopes = append(c.Scopes, "email") },
		"scope removed":    func(c *Client) { c.Scopes = []string{"basic"} },
	} {
		d := clone()
		edit(&d)
		if d.Matches(s) {
			t.Errorf("%s: matches", name)
		}
	}
	// Defaults are not drift: Keycloak's refresh-token default is true, and
	// "no PKCE" is an absent attribute, whatever the order of a list.
	d := clone()
	delete(d.rep.Attributes, refreshAttr)
	slices.Reverse(d.rep.RedirectURIs)
	d.Scopes = []string{"profile", "basic"}
	if !d.Matches(s) {
		t.Error("a default or a reordering is drift")
	}
	s.PKCE = "Disabled"
	delete(d.rep.Attributes, pkceAttr)
	if !d.Matches(s) {
		t.Error("disabled PKCE and an absent attribute differ")
	}
	// No post-logout URIs is "-": an absent attribute would let Keycloak
	// accept the redirect URIs.
	orig, none := spec(), spec()
	none.PostLogoutRedirectURIs = nil
	d = clone()
	if d.Matches(none) {
		t.Error("post-logout URIs where there should be none")
	}
	d.rep.Attributes[postLogoutAttr] = "-"
	if !d.Matches(none) || d.Matches(orig) {
		t.Error("the marker for no post-logout URIs is not understood")
	}
	delete(d.rep.Attributes, postLogoutAttr)
	if d.Matches(none) || d.Matches(orig) {
		t.Error("an absent attribute matches")
	}
}

func TestProbeFailure(t *testing.T) {
	f := newFakeKeycloak()
	f.rules = []rule{{"GET", "/clients", reply{status: 503}}}
	if err := newKeycloakFor(t, f).Probe(t.Context()); statusOf(err) != 503 {
		t.Fatalf("%v", err)
	}
}

// sweep runs op against a fake that answers the i-th request with each of the
// bad replies, for every i the clean run makes, and requires an error each
// time: every request of the operation is needed, so a failure of any of them
// must reach the caller.
func sweep(t *testing.T, setup func(*fakeKeycloak) string, op func(ctx context.Context, k *Keycloak, id string) error, ignore200 bool) {
	t.Helper()
	ctx := t.Context()
	f := newFakeKeycloak()
	id := setup(f)
	if err := op(ctx, newKeycloakFor(t, f), id); err != nil {
		t.Fatalf("the clean run failed: %v", err)
	}
	n := f.count()
	bad := []reply{{status: 500, body: `{"errorMessage":"boom https://10.0.0.1"}`}}
	if !ignore200 {
		bad = append(bad, reply{status: 200, body: "not json"})
	}
	for _, rp := range bad {
		for i := 1; i <= n; i++ {
			f := newFakeKeycloak()
			id := setup(f)
			f.failAt, f.failWith = i, rp
			err := op(ctx, newKeycloakFor(t, f), id)
			if err == nil {
				t.Errorf("request %d of %d answered %d %q: no error", i, n, rp.status, rp.body)
			} else if strings.Contains(err.Error(), "10.0.0.1") {
				t.Errorf("the error leaks the body: %v", err)
			}
		}
	}
}

func TestKeycloakEveryRequestMatters(t *testing.T) {
	s := spec()
	seeded := func(f *fakeKeycloak) string { f.rotation = true; return f.seed(s.ClientID, s.Marker) }
	t.Run("create", func(t *testing.T) {
		sweep(t, func(*fakeKeycloak) string { return "" }, func(ctx context.Context, k *Keycloak, _ string) error {
			_, err := k.Create(ctx, s)
			return err
		}, false)
	})
	t.Run("create over an earlier attempt", func(t *testing.T) {
		sweep(t, seeded, func(ctx context.Context, k *Keycloak, _ string) error {
			_, err := k.Create(ctx, s)
			return err
		}, false)
	})
	t.Run("update", func(t *testing.T) {
		sweep(t, seeded, func(ctx context.Context, k *Keycloak, id string) error { return k.Update(ctx, id, s) }, false)
	})
	t.Run("get", func(t *testing.T) {
		sweep(t, seeded, func(ctx context.Context, k *Keycloak, id string) error {
			_, err := k.Get(ctx, id, s.Marker)
			return err
		}, false)
	})
	t.Run("delete", func(t *testing.T) {
		sweep(t, seeded, func(ctx context.Context, k *Keycloak, id string) error { return k.Delete(ctx, id) }, false)
	})
	t.Run("rotate", func(t *testing.T) {
		sweep(t, func(f *fakeKeycloak) string {
			id := seeded(f)
			return id
		}, func(ctx context.Context, k *Keycloak, id string) error {
			_, err := k.Rotate(ctx, id, "secret-"+id)
			return err
		}, false)
	})
	t.Run("finish rotation", func(t *testing.T) {
		sweep(t, func(f *fakeKeycloak) string {
			id := seeded(f)
			f.client(id).rotated = "old"
			return id
		}, func(ctx context.Context, k *Keycloak, id string) error { return k.FinishRotation(ctx, id) }, true)
	})
	t.Run("probe", func(t *testing.T) {
		sweep(t, func(*fakeKeycloak) string { return "" }, func(ctx context.Context, k *Keycloak, _ string) error {
			return k.Probe(ctx)
		}, true)
	})
}

func TestNames(t *testing.T) {
	long := strings.Repeat("a", 253)
	for _, tc := range []struct {
		name       string
		got        string
		hashLength int
	}{
		{"keycloak", KeycloakClientID("team-a", "orders"), 10},
		{"keycloak long", KeycloakClientID("team-a", long), 10},
		// Markerless objects carry the long hash.
		{"dcr", DCRClientName("team-a", "orders"), 16},
		{"dcr long", DCRClientName("team-a", long), 16},
	} {
		i := strings.LastIndex(tc.got, "-")
		if len(tc.got) > 255 || len(tc.got)-i-1 != tc.hashLength {
			t.Errorf("%s: %q", tc.name, tc.got)
		}
	}
	if got := KeycloakClientID("team-a", "orders"); got != "team-a-orders-gdeqxvirep" {
		t.Errorf("%s", got)
	}
	if KeycloakClientID("team-a", "db") == KeycloakClientID("team", "a-db") {
		t.Error("two claims share a client_id")
	}
	if got := Marker("ns", "name", "uid"); got != "ns/name/uid" {
		t.Errorf("%s", got)
	}
}
