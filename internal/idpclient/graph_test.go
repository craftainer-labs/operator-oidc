package idpclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	appObj = "00000000-0000-0000-0000-0000000000a1"
	appCli = "00000000-0000-0000-0000-0000000000b1"
	key1   = "00000000-0000-0000-0000-0000000000c1"
	key2   = "00000000-0000-0000-0000-0000000000c2"
)

// graphFake answers the Graph calls the client makes and records them.
type graphFake struct {
	mu   sync.Mutex
	seen []string
	body map[string]map[string]any
	// answer maps "METHOD /path" to a status and a body.
	answer map[string]graphAnswer
	auth   string
}

type graphAnswer struct {
	status int
	body   string
}

func (f *graphFake) saw(call string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.seen, call)
}

func startGraph(t *testing.T, answer map[string]graphAnswer) (*Graph, *graphFake) {
	t.Helper()
	f := &graphFake{answer: answer, body: map[string]map[string]any{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		call := r.Method + " " + r.URL.Path
		f.seen = append(f.seen, call)
		f.auth = r.Header.Get("Authorization")
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err == nil {
				f.body[call] = m
			}
		}
		if r.URL.Path == "/v1.0/applications" && r.Method == http.MethodGet {
			f.seen[len(f.seen)-1] += "?" + r.URL.RawQuery
		}
		a, ok := f.answer[call]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(a.status)
		_, _ = io.WriteString(w, a.body)
	}))
	t.Cleanup(srv.Close)
	g, err := NewGraph(srv.Client(), srv.URL, func(context.Context) (string, error) { return "tok", nil })
	if err != nil {
		t.Fatal(err)
	}
	return g, f
}

func appJSON(extra string) string {
	return `{"id":"` + appObj + `","appId":"` + appCli + `","displayName":"n","signInAudience":"AzureADMyOrg",` +
		`"isFallbackPublicClient":false,"web":{"redirectUris":["https://a/cb"],"logoutUrl":null},"publicClient":{"redirectUris":[]}` + extra + `}`
}

func TestGraphProbeAndBearer(t *testing.T) {
	g, f := startGraph(t, map[string]graphAnswer{"GET /v1.0/applications": {200, `{"value":[]}`}})
	if err := g.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.auth != "Bearer tok" || !f.saw("GET /v1.0/applications?%24select=id&%24top=1") {
		t.Errorf("auth = %q, seen = %v", f.auth, f.seen)
	}
}

func TestGraphCreateSendsTheWholeApplication(t *testing.T) {
	g, f := startGraph(t, map[string]graphAnswer{"POST /v1.0/applications": {201, appJSON("")}})
	app, err := g.Create(t.Context(), GraphApp{DisplayName: "n", Audience: GraphAudience, WebRedirectURIs: []string{"https://a/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	if app.ID != appObj || app.AppID != appCli || !slices.Equal(app.WebRedirectURIs, []string{"https://a/cb"}) || app.LogoutURL != "" {
		t.Errorf("app = %+v", app)
	}
	b := f.body["POST /v1.0/applications"]
	web := b["web"].(map[string]any)
	pub := b["publicClient"].(map[string]any)
	if b["displayName"] != "n" || b["signInAudience"] != GraphAudience || b["isFallbackPublicClient"] != false ||
		len(web["redirectUris"].([]any)) != 1 || web["logoutUrl"] != nil || len(pub["redirectUris"].([]any)) != 0 {
		t.Errorf("body = %v", b)
	}

	// An answer with a bad ID is refused.
	g, _ = startGraph(t, map[string]graphAnswer{"POST /v1.0/applications": {201, `{"id":"../x","appId":"` + appCli + `"}`}})
	if _, err := g.Create(t.Context(), GraphApp{}); !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v", err)
	}
}

func TestGraphGetUpdateDelete(t *testing.T) {
	path := "/v1.0/applications/" + appObj
	g, f := startGraph(t, map[string]graphAnswer{
		"GET " + path:    {200, appJSON(`,"passwordCredentials":[{"keyId":"` + key1 + `","displayName":"craftainer-0"}]`)},
		"PATCH " + path:  {204, ""},
		"DELETE " + path: {204, ""},
	})
	app, err := g.Get(t.Context(), appObj)
	if err != nil || len(app.Passwords) != 1 || app.Passwords[0].KeyID != key1 || app.Passwords[0].DisplayName != "craftainer-0" {
		t.Fatalf("app = %+v, err = %v", app, err)
	}
	if err := g.Update(t.Context(), appObj, GraphApp{DisplayName: "n", LogoutURL: "https://a/out"}); err != nil {
		t.Fatal(err)
	}
	if web := f.body["PATCH "+path]["web"].(map[string]any); web["logoutUrl"] != "https://a/out" {
		t.Errorf("body = %v", f.body["PATCH "+path])
	}
	if err := g.Delete(t.Context(), appObj); err != nil {
		t.Fatal(err)
	}

	// A missing application is ErrNotFound; an answer that is not JSON is not an application.
	g, _ = startGraph(t, map[string]graphAnswer{"GET " + path: {404, `{"error":{"message":"secret detail"}}`}, "DELETE " + path: {404, ""}})
	for _, err := range []error{func() error { _, e := g.Get(t.Context(), appObj); return e }(), g.Delete(t.Context(), appObj)} {
		if !errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "secret detail") {
			t.Errorf("err = %v", err)
		}
	}
	g, _ = startGraph(t, map[string]graphAnswer{"GET " + path: {200, "<html>"}})
	if _, err := g.Get(t.Context(), appObj); !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v", err)
	}
}

func TestGraphPasswords(t *testing.T) {
	path := "/v1.0/applications/" + appObj
	g, f := startGraph(t, map[string]graphAnswer{
		"POST " + path + "/addPassword":    {200, `{"keyId":"` + key2 + `","secretText":"s3cret"}`},
		"POST " + path + "/removePassword": {204, ""},
	})
	sec, err := g.AddPassword(t.Context(), appObj, "craftainer-1")
	if err != nil || sec.KeyID != key2 || sec.Value != "s3cret" {
		t.Fatalf("secret = %+v, err = %v", sec, err)
	}
	if pc := f.body["POST "+path+"/addPassword"]["passwordCredential"].(map[string]any); pc["displayName"] != "craftainer-1" {
		t.Errorf("body = %v", f.body)
	}
	if err := g.RemovePassword(t.Context(), appObj, key1); err != nil {
		t.Fatal(err)
	}
	if f.body["POST "+path+"/removePassword"]["keyId"] != key1 {
		t.Errorf("body = %v", f.body)
	}

	// A secret answered without text is refused.
	g, _ = startGraph(t, map[string]graphAnswer{"POST " + path + "/addPassword": {200, `{"keyId":"` + key2 + `"}`}})
	if _, err := g.AddPassword(t.Context(), appObj, "x"); !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v", err)
	}

	// Graph answers 400 for a key the application does not hold: gone, if the
	// application no longer lists it; an error if it still does.
	g, _ = startGraph(t, map[string]graphAnswer{
		"POST " + path + "/removePassword": {400, ""},
		"GET " + path:                      {200, appJSON("")},
	})
	if err := g.RemovePassword(t.Context(), appObj, key1); err != nil {
		t.Errorf("a key that is gone: %v", err)
	}
	g, _ = startGraph(t, map[string]graphAnswer{
		"POST " + path + "/removePassword": {400, ""},
		"GET " + path:                      {200, appJSON(`,"passwordCredentials":[{"keyId":"` + key1 + `","displayName":"x"}]`)},
	})
	var e *Error
	if err := g.RemovePassword(t.Context(), appObj, key1); !errors.As(err, &e) || e.Status != 400 {
		t.Errorf("a key that is still there: %v", err)
	}
}

// An ID that is no GUID never reaches a path, and a token that cannot be fetched
// is its own error, without the cause's text in ours.
func TestGraphInputsAndTokenFailures(t *testing.T) {
	g, f := startGraph(t, nil)
	for _, bad := range []string{"", "../applications", appObj + "/x", "a b"} {
		if _, err := g.Get(t.Context(), bad); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Get(%q) = %v", bad, err)
		}
		if err := g.Delete(t.Context(), bad); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Delete(%q) = %v", bad, err)
		}
	}
	if err := g.RemovePassword(t.Context(), appObj, "nope"); !errors.Is(err, ErrInvalidID) || len(f.seen) != 0 {
		t.Errorf("err = %v, seen = %v", err, f.seen)
	}

	fail, _ := NewGraph(http.DefaultClient, "https://graph.example", func(context.Context) (string, error) { return "", errors.New("AADSTS70011") })
	if err := fail.Probe(t.Context()); !errors.Is(err, ErrGraphToken) {
		t.Errorf("err = %v", err)
	}
	for _, base := range []string{"", "ftp://x", "https://", "https://u:p@x", "http://x", "https://x?a=b", "https://x#f"} {
		if _, err := NewGraph(http.DefaultClient, base, func(context.Context) (string, error) { return "", nil }); !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("NewGraph(%q) = %v", base, err)
		}
	}
	if _, err := NewGraph(nil, "https://x", func(context.Context) (string, error) { return "", nil }); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("err = %v", err)
	}
}

func TestGraphStatusesAreCategories(t *testing.T) {
	g, _ := startGraph(t, map[string]graphAnswer{"GET /v1.0/applications": {403, `{"error":{"message":"Insufficient privileges"}}`}})
	err := g.Probe(t.Context())
	if !errors.Is(err, ErrConnAuth) || strings.Contains(err.Error(), "Insufficient") {
		t.Errorf("err = %v", err)
	}
}

func TestEntraAppName(t *testing.T) {
	long := strings.Repeat("a", 200)
	got := EntraAppName("team", long)
	if len(got) > maxEntraAppNameLen || got == EntraAppName("team", long+"b") {
		t.Errorf("name = %q", got)
	}
}

func TestGraphMoreFailures(t *testing.T) {
	path := "/v1.0/applications/" + appObj
	g, _ := startGraph(t, map[string]graphAnswer{
		"POST /v1.0/applications":          {400, ""},
		"PATCH " + path:                    {400, ""},
		"POST " + path + "/addPassword":    {400, ""},
		"POST " + path + "/removePassword": {500, ""},
	})
	if _, err := g.Create(t.Context(), GraphApp{}); err == nil {
		t.Error("a refused create succeeded")
	}
	if err := g.Update(t.Context(), "nope", GraphApp{}); !errors.Is(err, ErrInvalidID) {
		t.Errorf("err = %v", err)
	}
	if err := g.Update(t.Context(), appObj, GraphApp{}); err == nil {
		t.Error("a refused update succeeded")
	}
	if _, err := g.AddPassword(t.Context(), "nope", "x"); !errors.Is(err, ErrInvalidID) {
		t.Errorf("err = %v", err)
	}
	if _, err := g.AddPassword(t.Context(), appObj, "x"); err == nil {
		t.Error("a refused addPassword succeeded")
	}
	if err := g.RemovePassword(t.Context(), appObj, key1); err == nil {
		t.Error("a failed removePassword succeeded")
	}

	g, _ = startGraph(t, map[string]graphAnswer{"POST " + path + "/addPassword": {200, "<html>"}})
	if _, err := g.AddPassword(t.Context(), appObj, "x"); !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v", err)
	}
}

func TestGraphReadsLogoutURLAndRefusesBadKeyIDs(t *testing.T) {
	path := "/v1.0/applications/" + appObj
	withLogout := strings.Replace(appJSON(""), `"logoutUrl":null`, `"logoutUrl":"https://a/out"`, 1)
	g, _ := startGraph(t, map[string]graphAnswer{"GET " + path: {200, withLogout}})
	if app, err := g.Get(t.Context(), appObj); err != nil || app.LogoutURL != "https://a/out" {
		t.Errorf("app = %+v, err = %v", app, err)
	}
	g, _ = startGraph(t, map[string]graphAnswer{"GET " + path: {200, appJSON(`,"passwordCredentials":[{"keyId":"x/../y"}]`)}})
	if _, err := g.Get(t.Context(), appObj); !errors.Is(err, ErrBadResponse) {
		t.Errorf("err = %v", err)
	}
}

func TestGraphConnectionFailureIsACategory(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	g, err := NewGraph(srv.Client(), srv.URL, func(context.Context) (string, error) { return "tok", nil })
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if err := g.Probe(t.Context()); !errors.Is(err, ErrConnFailed) {
		t.Errorf("err = %v", err)
	}
}
