package controller

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// recorder keeps the Events of a test.
type recorder struct {
	mu     sync.Mutex
	events []string
}

// Eventf implements events.EventRecorder: it keeps "<type> <reason>: <note>".
func (r *recorder) Eventf(_, _ runtime.Object, eventType, reason, _, note string, args ...any) {
	if len(args) > 0 {
		note = fmt.Sprintf(note, args...)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, eventType+" "+reason+": "+note)
}

func (r *recorder) has(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.ContainsFunc(r.events, func(e string) bool { return strings.HasPrefix(e, prefix) })
}

// kcScope is a client scope of the fake realm.
type kcScope struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// kcState is the Admin REST state of the fake realm "main": the clients, the
// client scopes, the secrets and what the test forces to fail. Keycloak's own
// defaults are what a new client gets: the roles, profile, email and basic
// scopes.
type kcState struct {
	mu       sync.Mutex
	clients  map[string]map[string]any
	defaults map[string][]string
	secrets  map[string]string
	rotated  map[string]string
	n        int
	// noRotated makes the realm keep no rotated secret (no client policy).
	noRotated bool
	// fail maps "METHOD /path-below-the-realm" to the status the fake answers.
	fail map[string]int
	log  []string
}

var realmScopes = []kcScope{{"sc-roles", "roles"}, {"sc-profile", "profile"}, {"sc-email", "email"}, {"sc-basic", "basic"}, {"sc-offline", "offline_access"}}

var realmDefaults = []string{"roles", "profile", "email", "basic"}

func scopeID(name string) string {
	for _, s := range realmScopes {
		if s.Name == name {
			return s.ID
		}
	}
	return ""
}

func scopeName(id string) string {
	for _, s := range realmScopes {
		if s.ID == id {
			return s.Name
		}
	}
	return ""
}

// saw reports whether a request "METHOD path" (below the realm) was made.
func (k *kcState) saw(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Contains(k.log, key)
}

// count is how many requests "METHOD path" were made.
func (k *kcState) count(key string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, l := range k.log {
		if l == key {
			n++
		}
	}
	return n
}

func (k *kcState) failing(key string, status int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail == nil {
		k.fail = map[string]int{}
	}
	if status == 0 {
		delete(k.fail, key)
		return
	}
	k.fail[key] = status
}

// with runs f on the client id under the lock.
func (k *kcState) with(f func()) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// serve answers an Admin REST request of the realm.
func (k *kcState) serve(w http.ResponseWriter, r *http.Request, base string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.clients == nil {
		k.clients, k.defaults, k.secrets, k.rotated = map[string]map[string]any{}, map[string][]string{}, map[string]string{}, map[string]string{}
	}
	rel := strings.TrimPrefix(r.URL.Path, "/admin/realms/main")
	key := r.Method + " " + rel
	k.log = append(k.log, key)
	if st, ok := k.fail[key]; ok {
		w.WriteHeader(st)
		return
	}
	segs := strings.Split(strings.Trim(rel, "/"), "/")
	switch {
	case rel == "/client-scopes":
		writeJSON(w, http.StatusOK, realmScopes)
	case rel == "/clients" && r.Method == http.MethodGet:
		list := []map[string]any{}
		for _, c := range k.clients {
			if want := r.URL.Query().Get("clientId"); want == "" || c["clientId"] == want {
				list = append(list, c)
			}
		}
		writeJSON(w, http.StatusOK, list)
	case rel == "/clients" && r.Method == http.MethodPost:
		k.create(w, r, base)
	case len(segs) >= 2 && segs[0] == "clients":
		k.client(w, r, segs[1], segs[2:])
	default:
		http.NotFound(w, r)
	}
}

func (k *kcState) create(w http.ResponseWriter, r *http.Request, base string) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	for _, c := range k.clients {
		if c["clientId"] == body["clientId"] {
			w.WriteHeader(http.StatusConflict)
			return
		}
	}
	k.n++
	id := fmt.Sprintf("kc-%d", k.n)
	body["id"] = id
	k.clients[id] = body
	k.defaults[id] = slices.Clone(realmDefaults)
	k.secrets[id] = fmt.Sprintf("secret-%d-0", k.n)
	w.Header().Set("Location", base+"/admin/realms/main/clients/"+id)
	w.WriteHeader(http.StatusCreated)
}

func (k *kcState) client(w http.ResponseWriter, r *http.Request, id string, sub []string) {
	c, ok := k.clients[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch {
	case len(sub) == 0 && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, c)
	case len(sub) == 0 && r.Method == http.MethodPut:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["id"] = id
		k.clients[id] = body
		w.WriteHeader(http.StatusNoContent)
	case len(sub) == 0 && r.Method == http.MethodDelete:
		delete(k.clients, id)
		w.WriteHeader(http.StatusNoContent)
	case sub[0] == "default-client-scopes":
		k.scopes(w, r, id, sub[1:])
	case sub[0] == "client-secret":
		k.secret(w, r, id, sub[1:])
	default:
		http.NotFound(w, r)
	}
}

func (k *kcState) scopes(w http.ResponseWriter, r *http.Request, id string, sub []string) {
	switch {
	case len(sub) == 0:
		list := []kcScope{}
		for _, n := range k.defaults[id] {
			list = append(list, kcScope{scopeID(n), n})
		}
		writeJSON(w, http.StatusOK, list)
	case r.Method == http.MethodPut:
		k.defaults[id] = append(k.defaults[id], scopeName(sub[0]))
		w.WriteHeader(http.StatusNoContent)
	default:
		k.defaults[id] = slices.DeleteFunc(k.defaults[id], func(n string) bool { return n == scopeName(sub[0]) })
		w.WriteHeader(http.StatusNoContent)
	}
}

func (k *kcState) secret(w http.ResponseWriter, r *http.Request, id string, sub []string) {
	switch {
	case len(sub) == 1 && r.Method == http.MethodGet:
		v, ok := k.rotated[id]
		if !ok || k.noRotated {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"value": v})
	case len(sub) == 1:
		delete(k.rotated, id)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost:
		k.rotated[id] = k.secrets[id]
		k.secrets[id] += "+"
		writeJSON(w, http.StatusOK, map[string]string{"value": k.secrets[id]})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"value": k.secrets[id]})
	}
}

// dcrFake is a provider that registers clients (RFC 7591 and 7592) over TLS.
type dcrFake struct {
	srv *httptest.Server
	ca  []byte

	mu sync.Mutex
	// clients holds the registered metadata by client_id.
	clients map[string]map[string]any
	// tokens holds the registration access token by client_id.
	tokens map[string]string
	n      int
	// badRegister answers a registration with a document that has no client_id.
	badRegister bool
	// newToken makes every answer carry a new registration access token.
	newToken bool
	// newTokenOnPut makes only an update answer with a new token.
	newTokenOnPut bool
	// updateSecret makes an update answer with a new client secret.
	updateSecret bool
	// fail maps "METHOD /path" to the status answered.
	fail map[string]int
	log  []string
}

func startDCR(t *testing.T) *dcrFake {
	t.Helper()
	f := &dcrFake{clients: map[string]map[string]any{}, tokens: map[string]string{}, fail: map[string]int{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return f
}

func (f *dcrFake) endpoint() string { return f.srv.URL + "/register" }

func (f *dcrFake) saw(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.log, key)
}

func (f *dcrFake) with(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *dcrFake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	f.log = append(f.log, key)
	if st, ok := f.fail[key]; ok {
		w.WriteHeader(st)
		return
	}
	if r.URL.Path == "/register" && r.Method == http.MethodPost {
		f.register(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/register/")
	meta, ok := f.clients[id]
	if !ok || r.Header.Get("Authorization") != "Bearer "+f.tokens[id] {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		delete(f.clients, id)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		body["client_id"] = id
		f.clients[id] = body
		meta = body
		fallthrough
	default:
		answer := map[string]any{"registration_client_uri": f.srv.URL + "/register/" + id}
		for k, v := range meta {
			answer[k] = v
		}
		if f.newToken || (f.newTokenOnPut && r.Method == http.MethodPut) {
			f.tokens[id] += "+"
			answer["registration_access_token"] = f.tokens[id]
		}
		if f.updateSecret && r.Method == http.MethodPut {
			answer["client_secret"] = "updated-secret"
		}
		writeJSON(w, http.StatusOK, answer)
	}
}

func (f *dcrFake) register(w http.ResponseWriter, r *http.Request) {
	if f.badRegister {
		writeJSON(w, http.StatusCreated, map[string]any{})
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.n++
	id := fmt.Sprintf("dcr-%d", f.n)
	body["client_id"] = id
	f.clients[id] = body
	f.tokens[id] = fmt.Sprintf("rat-%d", f.n)
	answer := map[string]any{
		"registration_client_uri": f.srv.URL + "/register/" + id, "registration_access_token": f.tokens[id],
		"client_secret": fmt.Sprintf("dcr-secret-%d", f.n),
	}
	for k, v := range body {
		answer[k] = v
	}
	writeJSON(w, http.StatusCreated, answer)
}

func caConfigMapOf(ns string, ca []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ca"}, Data: map[string]string{"ca.crt": string(ca)}}
}
