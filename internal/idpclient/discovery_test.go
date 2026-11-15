package idpclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// discoveryFake serves the document of the issuer it is started for, with
// doc's fields filled in by edit.
func discoveryFake(t *testing.T, path string, edit func(map[string]any)) (string, Transport) {
	t.Helper()
	var issuer string
	srv, tr := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path+"/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		doc := map[string]any{
			"issuer":                 issuer,
			"token_endpoint":         issuer + "/token",
			"authorization_endpoint": issuer + "/auth",
			"jwks_uri":               issuer + "/certs",
			"userinfo_endpoint":      issuer + "/userinfo",
		}
		if edit != nil {
			edit(doc)
		}
		b, _ := json.Marshal(doc)
		_, _ = w.Write(b)
	}))
	issuer = srv.URL + path
	return issuer, tr
}

func TestDiscover(t *testing.T) {
	for _, path := range []string{"", "/realms/main"} {
		issuer, tr := discoveryFake(t, path, nil)
		got, err := Discover(context.Background(), tr, issuer)
		if err != nil {
			t.Fatalf("path %q: %v", path, err)
		}
		want := Discovery{
			TokenEndpoint: issuer + "/token", AuthorizationEndpoint: issuer + "/auth",
			JWKSURI: issuer + "/certs", UserinfoEndpoint: issuer + "/userinfo",
		}
		if got != want {
			t.Errorf("path %q: got %+v, want %+v", path, got, want)
		}
	}
}

func TestDiscoverAcceptsMissingEndpoints(t *testing.T) {
	issuer, tr := discoveryFake(t, "", func(d map[string]any) {
		delete(d, "authorization_endpoint")
		delete(d, "userinfo_endpoint")
	})
	got, err := Discover(context.Background(), tr, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthorizationEndpoint != "" || got.UserinfoEndpoint != "" || got.TokenEndpoint == "" {
		t.Errorf("got %+v", got)
	}
}

func TestDiscoverRefusals(t *testing.T) {
	long := "https://idp.example/" + strings.Repeat("a", maxEndpointLen)
	cases := map[string]func(map[string]any){
		"another issuer":        func(d map[string]any) { d["issuer"] = "https://other.example" },
		"an http endpoint":      func(d map[string]any) { d["token_endpoint"] = "http://idp.example/token" },
		"a userinfo in the URL": func(d map[string]any) { d["jwks_uri"] = "https://u:p@idp.example/certs" },
		"a long endpoint":       func(d map[string]any) { d["userinfo_endpoint"] = long },
		"a non-string endpoint": func(d map[string]any) { d["token_endpoint"] = 7 },
	}
	for name, edit := range cases {
		issuer, tr := discoveryFake(t, "", edit)
		_, err := Discover(context.Background(), tr, issuer)
		if !errors.Is(err, ErrBadResponse) {
			t.Errorf("%s: got %v, want ErrBadResponse", name, err)
		}
	}
}

func TestDiscoverFailures(t *testing.T) {
	issuer, tr := discoveryFake(t, "", nil)
	ctx := context.Background()
	if _, err := Discover(ctx, tr, "http://idp.example"); !errors.Is(err, ErrInvalidEndpoint) {
		t.Errorf("an http issuer: %v", err)
	}
	if _, err := Discover(ctx, Transport{}, issuer); !errors.Is(err, ErrNoDialer) {
		t.Errorf("no dialer: %v", err)
	}
	// The fake only knows the discovery path of its own issuer.
	var e *Error
	if _, err := Discover(ctx, tr, issuer+"/elsewhere"); !errors.As(err, &e) || e.Status != http.StatusNotFound {
		t.Errorf("a missing document: %v", err)
	}
	srv, tr2 := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	if _, err := Discover(ctx, tr2, srv.URL); !errors.Is(err, ErrConnAuth) {
		t.Errorf("a refusal: %v", err)
	}
	srv, tr3 := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) }))
	if _, err := Discover(ctx, tr3, srv.URL); !errors.Is(err, ErrBadResponse) {
		t.Errorf("a broken document: %v", err)
	}
	srv, tr4 := startTLS(t, http.NotFoundHandler())
	srv.Close()
	if _, err := Discover(ctx, tr4, srv.URL); !errors.Is(err, ErrConnFailed) {
		t.Errorf("an unreachable provider: %v", err)
	}
}
