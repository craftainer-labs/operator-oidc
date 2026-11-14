package idpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// direct dials without the egress policy: the fakes listen on loopback, which
// the policy refuses (see TestTransportCategories for the policy itself).
func direct(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func pemOf(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

// startTLS serves h over TLS and returns the server and a Transport that
// trusts it.
func startTLS(t *testing.T, h http.Handler) (*httptest.Server, Transport) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, Transport{CABundle: pemOf(srv), Dial: direct}
}

// reply is a canned answer.
type reply struct {
	status int
	body   string
	header map[string]string
}

func (rp reply) write(w http.ResponseWriter) {
	for k, v := range rp.header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(rp.status)
	_, _ = io.WriteString(w, rp.body)
}

func jsonReply(status int, v any) reply {
	b, _ := json.Marshal(v)
	return reply{status: status, body: string(b)}
}

// recorder counts the requests of a fake and overrides some of its answers.
type recorder struct {
	mu   sync.Mutex
	n    int
	seen []string
	// failAt is the 1-based number of the request answered with failWith
	// instead of by the fake; 0 is none.
	failAt   int
	failWith reply
	// rules answer every request they match, before the fake does.
	rules []rule
	// bodies are the request bodies by "METHOD path".
	bodies map[string][]byte
	// auth is the Authorization header of every request, by "METHOD path".
	auth map[string]string
}

type rule struct {
	method, suffix string
	reply          reply
}

// forced returns the override of the request, if any. The caller holds mu.
func (r *recorder) forced(req *http.Request) (reply, bool) {
	r.n++
	key := req.Method + " " + req.URL.Path
	r.seen = append(r.seen, key)
	if r.bodies == nil {
		r.bodies, r.auth = map[string][]byte{}, map[string]string{}
	}
	b, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(b))
	r.bodies[key], r.auth[key] = b, req.Header.Get("Authorization")
	if r.failAt == r.n {
		return r.failWith, true
	}
	for _, ru := range r.rules {
		if ru.method == req.Method && strings.HasSuffix(req.URL.Path, ru.suffix) {
			return ru.reply, true
		}
	}
	return reply{}, false
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func (r *recorder) saw(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.seen {
		if s == key {
			n++
		}
	}
	return n
}

func (r *recorder) body(key string) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var m map[string]any
	_ = json.Unmarshal(r.bodies[key], &m)
	return m
}

// fakeKeycloak is the part of Keycloak's Admin REST API the client uses, for
// the realm "test", with one service account.
type fakeKeycloak struct {
	recorder
	// rotation says that the realm has a secret-rotation client policy.
	rotation bool
	tokens   int
	seq      int
	clients  map[string]*kcClient
	// ttl is the expires_in of a token.
	ttl int
}

type kcClient struct {
	rep     map[string]any
	scopes  []string // scope ids
	secret  string
	rotated string
	regens  int
}

var realmScopes = []scopeRep{
	{ID: "sc-basic", Name: "basic"}, {ID: "sc-profile", Name: "profile"},
	{ID: "sc-email", Name: "email"}, {ID: "sc-roles", Name: "roles"},
}

const kcAdmin = "/admin/realms/test"

func newFakeKeycloak() *fakeKeycloak {
	return &fakeKeycloak{clients: map[string]*kcClient{}, ttl: 60}
}

// seed adds a client with the given client_id and marker, as if made by an
// earlier attempt (or by hand), and returns its id.
func (f *fakeKeycloak) seed(clientID, marker string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := "id-" + strconv.Itoa(f.seq)
	f.clients[id] = &kcClient{
		rep:    map[string]any{"id": id, "clientId": clientID, "attributes": map[string]any{markerAttr: marker}},
		secret: "secret-" + id,
	}
	return id
}

func (f *fakeKeycloak) client(id string) *kcClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clients[id]
}

func (f *fakeKeycloak) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rp, ok := f.forced(r)
	if !ok {
		rp = f.route(r)
	}
	rp.write(w)
}

func (f *fakeKeycloak) route(r *http.Request) reply {
	p := r.URL.Path
	switch {
	case p == "/realms/test/protocol/openid-connect/token":
		return f.token(r)
	case p == kcAdmin+"/client-scopes":
		return jsonReply(200, realmScopes)
	case p == kcAdmin+"/clients":
		return f.clientsRoot(r)
	case strings.HasPrefix(p, kcAdmin+"/clients/"):
		parts := strings.Split(strings.TrimPrefix(p, kcAdmin+"/clients/"), "/")
		c, ok := f.clients[parts[0]]
		if !ok {
			return reply{status: 404, body: `{"error":"Could not find client"}`}
		}
		return f.clientRoute(r, parts[0], c, parts[1:])
	}
	return reply{status: 404}
}

func (f *fakeKeycloak) token(r *http.Request) reply {
	_ = r.ParseForm()
	if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "operator" ||
		r.PostForm.Get("client_secret") != "operator-secret" {
		return reply{status: 401, body: `{"error":"invalid_client","error_description":"secret operator-secret"}`}
	}
	f.tokens++
	return jsonReply(200, map[string]any{"access_token": "token-" + strconv.Itoa(f.tokens), "expires_in": f.ttl})
}

func (f *fakeKeycloak) clientsRoot(r *http.Request) reply {
	if r.Header.Get("Authorization") == "" {
		return reply{status: 401}
	}
	if r.Method == http.MethodGet {
		out := []map[string]any{}
		for _, c := range f.clients {
			if want := r.URL.Query().Get("clientId"); want == "" || c.rep["clientId"] == want {
				out = append(out, c.rep)
			}
		}
		return jsonReply(200, out)
	}
	var rep map[string]any
	_ = json.NewDecoder(r.Body).Decode(&rep)
	for _, c := range f.clients {
		if c.rep["clientId"] == rep["clientId"] {
			return reply{status: 409, body: `{"errorMessage":"Client x already exists"}`}
		}
	}
	f.seq++
	id := "id-" + strconv.Itoa(f.seq)
	rep["id"] = id
	f.clients[id] = &kcClient{rep: rep, scopes: []string{"sc-profile", "sc-email", "sc-roles"}, secret: "secret-" + id}
	return reply{status: 201, header: map[string]string{"Location": "https://kc.invalid" + kcAdmin + "/clients/" + id}}
}

func (f *fakeKeycloak) clientRoute(r *http.Request, id string, c *kcClient, sub []string) reply {
	switch strings.Join(sub, "/") {
	case "":
		switch r.Method {
		case http.MethodGet:
			return jsonReply(200, c.rep)
		case http.MethodPut:
			// Keycloak drops what a PUT leaves out: the stored object is
			// the body.
			var rep map[string]any
			_ = json.NewDecoder(r.Body).Decode(&rep)
			c.rep = rep
			return reply{status: 204}
		}
		delete(f.clients, id)
		return reply{status: 204}
	case "default-client-scopes":
		out := []scopeRep{}
		for _, sid := range c.scopes {
			out = append(out, scopeRep{ID: sid, Name: scopeName(sid)})
		}
		return jsonReply(200, out)
	case "client-secret":
		if r.Method == http.MethodPost {
			c.regens++
			if f.rotation {
				c.rotated = c.secret
			}
			c.secret = "secret-" + id + "-" + strconv.Itoa(c.regens)
		}
		return jsonReply(200, map[string]string{"type": "secret", "value": c.secret})
	case "client-secret/rotated":
		if c.rotated == "" {
			return reply{status: 404, body: `{"error":"Client does not have a rotated secret"}`}
		}
		if r.Method == http.MethodDelete {
			c.rotated = ""
			return reply{status: 204}
		}
		return jsonReply(200, map[string]string{"type": "secret", "value": c.rotated})
	}
	// default-client-scopes/<id>
	sid := sub[1]
	if r.Method == http.MethodPut {
		c.scopes = append(c.scopes, sid)
		return reply{status: 204}
	}
	for i, s := range c.scopes {
		if s == sid {
			c.scopes = append(c.scopes[:i], c.scopes[i+1:]...)
			break
		}
	}
	return reply{status: 204}
}

func scopeName(id string) string {
	for _, s := range realmScopes {
		if s.ID == id {
			return s.Name
		}
	}
	return id
}

// newKeycloakFor starts a fake and a client of it.
func newKeycloakFor(t *testing.T, f *fakeKeycloak) *Keycloak {
	t.Helper()
	srv, tr := startTLS(t, f)
	k, err := NewKeycloak(KeycloakTarget{
		Transport: tr, BaseURL: srv.URL, Realm: "test", ClientID: "operator", ClientSecret: "operator-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}
