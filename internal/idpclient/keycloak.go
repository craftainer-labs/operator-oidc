package idpclient

import (
	"context"
	"crypto/subtle"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
)

// Names of the Keycloak client attributes and scopes this client owns.
const (
	// markerAttr holds the ownership marker (ADR 0002 section 10).
	markerAttr = "craftainer.dev/claim"
	// postLogoutAttr holds the post-logout redirect URIs, joined by "##".
	postLogoutAttr = "post.logout.redirect.uris"
	// noPostLogout is the value for an empty list. An absent attribute makes
	// Keycloak accept the client's redirect URIs for a post-logout redirect, so
	// "no post-logout redirect" is written out: "-" is no URI.
	noPostLogout = "-"
	// pkceAttr holds the PKCE code challenge method Keycloak requires.
	pkceAttr = "pkce.code.challenge.method"
	// refreshAttr says whether refresh tokens are issued.
	refreshAttr = "use.refresh.tokens"

	// basicScope carries the sub claim; every client keeps it, and the
	// spec's scopes never name it.
	basicScope = "basic"
	// openidScope is implicit in Keycloak and is no client scope.
	openidScope = "openid"

	grantAuthorizationCode = "authorization_code"
	grantClientCredentials = "client_credentials"
	grantRefreshToken      = "refresh_token"

	pkceDisabled = "Disabled"
	pkceS256     = "S256"

	jsonType = "application/json"
	// tokenSkew is how long before its expiry an admin token is renewed.
	tokenSkew = 15 * time.Second
)

var (
	// ErrNameCollision means a client of that name exists and its marker names
	// another claim: it is not ours to adopt, change or delete.
	ErrNameCollision = lifecycle.ErrNameCollision
	// ErrUnknownScope means the spec names a scope the realm has no client
	// scope for.
	ErrUnknownScope = errors.New("a scope of the client is not a client scope of the realm")
)

// realmPattern is the CRD's keycloak.realm pattern.
var realmPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// KeycloakTarget is one Keycloak realm: where to go, who to be and how to
// trust it.
type KeycloakTarget struct {
	Transport
	// BaseURL is the https URL of the Keycloak server (with its path, if any).
	BaseURL string
	// Realm is the realm whose clients are managed. The service account below
	// is a client of the same realm.
	Realm string
	// ClientID and ClientSecret are those of a service account that may manage
	// the realm's clients (the client roles manage-clients and, to read the
	// client scopes, view-clients of realm-management).
	ClientID, ClientSecret string
}

// Keycloak manages clients of one realm through the Admin REST API. It is safe
// for concurrent use.
type Keycloak struct {
	conn         *conn
	base         *url.URL
	realm        string
	clientID     string
	clientSecret string
	now          func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewKeycloak validates the target and builds its client. It makes no request.
func NewKeycloak(t KeycloakTarget) (*Keycloak, error) {
	base, err := parseHTTPS(t.BaseURL)
	if err != nil {
		return nil, err
	}
	if !realmPattern.MatchString(t.Realm) || t.Realm == "." || t.Realm == ".." {
		return nil, ErrInvalidRealm
	}
	if t.ClientID == "" || t.ClientSecret == "" {
		return nil, ErrNoCredentials
	}
	c, err := newConn(t.Transport)
	if err != nil {
		return nil, err
	}
	return &Keycloak{
		conn: c, base: base, realm: t.Realm, clientID: t.ClientID, clientSecret: t.ClientSecret, now: time.Now,
	}, nil
}

// CloseIdleConnections closes the idle connections; the controllers call it
// when they drop a cached client.
func (k *Keycloak) CloseIdleConnections() { k.conn.CloseIdleConnections() }

// ClientSpec is the desired state of one client. The controller derives
// ClientID with KeycloakClientID and Marker with Marker; nothing else of it is
// chosen by the claim's name.
type ClientSpec struct {
	// ClientID is the client_id.
	ClientID string
	// Marker is the ownership marker.
	Marker string
	// Public makes the client public: no secret.
	Public bool
	// RedirectURIs may be empty: a client_credentials-only client has none.
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	WebOrigins             []string
	// GrantTypes are OAuth grant names; empty means authorization_code, the
	// CRD's default.
	GrantTypes []string
	// PKCE is "S256" or "Disabled"; anything else is S256.
	PKCE string
	// Scopes are the client's default client scopes (besides Keycloak's
	// basic). "openid" is implicit in Keycloak and is ignored.
	Scopes []string
}

func (s ClientSpec) check() error {
	if s.ClientID == "" || s.Marker == "" {
		return ErrInvalidSpec
	}
	return nil
}

func (s ClientSpec) grants() []string {
	if len(s.GrantTypes) == 0 {
		return []string{grantAuthorizationCode}
	}
	return s.GrantTypes
}

// scopeNames are the spec's scopes as client scope names.
func (s ClientSpec) scopeNames() []string {
	var out []string
	for _, n := range s.Scopes {
		if n != openidScope && n != basicScope {
			out = append(out, n)
		}
	}
	return out
}

// owned are the fields of the client's representation this client sets.
func (s ClientSpec) owned() map[string]any {
	g := s.grants()
	return map[string]any{
		"clientId":                  s.ClientID,
		"enabled":                   true,
		"protocol":                  "openid-connect",
		"publicClient":              s.Public,
		"bearerOnly":                false,
		"standardFlowEnabled":       slices.Contains(g, grantAuthorizationCode),
		"serviceAccountsEnabled":    slices.Contains(g, grantClientCredentials),
		"implicitFlowEnabled":       false,
		"directAccessGrantsEnabled": false,
		"clientAuthenticatorType":   "client-secret",
		"redirectUris":              nonNil(s.RedirectURIs),
		"webOrigins":                nonNil(s.WebOrigins),
	}
}

// attributes are the attributes this client sets. The PKCE attribute is empty
// when PKCE is disabled: Keycloak drops an empty attribute, and keeps one a PUT
// leaves out.
func (s ClientSpec) attributes() map[string]string {
	a := map[string]string{
		markerAttr:     s.Marker,
		postLogoutAttr: postLogoutValue(s.PostLogoutRedirectURIs),
		refreshAttr:    strconv.FormatBool(slices.Contains(s.grants(), grantRefreshToken)),
		pkceAttr:       "",
	}
	if s.PKCE != pkceDisabled {
		a[pkceAttr] = pkceS256
	}
	return a
}

// body is the representation to create or update the client with: raw, the
// representation read before (nil for a new client), under the fields and
// attributes this client owns. Whatever else Keycloak keeps (mappers, the
// attributes an administrator set) stays, because an update sends the whole
// representation and Keycloak drops what a PUT leaves out.
func (s ClientSpec) body(raw map[string]any) []byte {
	out := map[string]any{}
	maps.Copy(out, raw)
	maps.Copy(out, s.owned())
	attrs := map[string]any{}
	if cur, ok := raw["attributes"].(map[string]any); ok {
		maps.Copy(attrs, cur)
	}
	for k, v := range s.attributes() {
		attrs[k] = v
	}
	out["attributes"] = attrs
	return mustJSON(out)
}

// representation is the part of Keycloak's ClientRepresentation read back.
type representation struct {
	ID                        string            `json:"id"`
	ClientID                  string            `json:"clientId"`
	Enabled                   bool              `json:"enabled"`
	PublicClient              bool              `json:"publicClient"`
	BearerOnly                bool              `json:"bearerOnly"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	RedirectURIs              []string          `json:"redirectUris"`
	WebOrigins                []string          `json:"webOrigins"`
	Attributes                map[string]string `json:"attributes"`
}

// Client is a client as Keycloak holds it.
type Client struct {
	// ID is Keycloak's own id of the client (what the Admin REST paths use).
	ID string
	// ClientID is the OIDC client_id.
	ClientID string
	// Public is whether the client has no secret.
	Public bool
	// Scopes are the names of the client's default client scopes.
	Scopes []string

	rep representation
}

// Matches reports whether the client is as the spec wants it, in every field
// this client sets.
func (c Client) Matches(s ClientSpec) bool {
	g := s.grants()
	a := c.rep.Attributes
	pkce := ""
	if s.PKCE != pkceDisabled {
		pkce = pkceS256
	}
	refresh := a[refreshAttr]
	if refresh == "" {
		refresh = "true" // Keycloak's default
	}
	return c.rep.ClientID == s.ClientID && c.rep.Enabled && !c.rep.BearerOnly && !c.rep.ImplicitFlowEnabled && !c.rep.DirectAccessGrantsEnabled &&
		c.rep.PublicClient == s.Public &&
		c.rep.StandardFlowEnabled == slices.Contains(g, grantAuthorizationCode) &&
		c.rep.ServiceAccountsEnabled == slices.Contains(g, grantClientCredentials) &&
		sameSet(c.rep.RedirectURIs, s.RedirectURIs) && sameSet(c.rep.WebOrigins, s.WebOrigins) &&
		postLogoutMatches(a[postLogoutAttr], s.PostLogoutRedirectURIs) &&
		a[pkceAttr] == pkce && refresh == strconv.FormatBool(slices.Contains(g, grantRefreshToken)) &&
		sameSet(slices.DeleteFunc(slices.Clone(c.Scopes), isBasic), s.scopeNames())
}

func isBasic(name string) bool { return name == basicScope }

func postLogoutValue(uris []string) string {
	if len(uris) == 0 {
		return noPostLogout
	}
	return strings.Join(uris, "##")
}

// postLogoutMatches reports whether the attribute holds exactly the wanted
// URIs; for none, only the explicit marker does, not an absent attribute.
func postLogoutMatches(attr string, want []string) bool {
	if len(want) == 0 {
		return attr == noPostLogout
	}
	return sameSet(strings.Split(attr, "##"), want)
}

// admin is the URL of an Admin REST path of the realm.
func (k *Keycloak) admin(segs ...string) *url.URL {
	return k.base.JoinPath(append([]string{"admin", "realms", k.realm}, segs...)...)
}

// bearer returns an admin token, asking for a new one when the last has
// expired.
func (k *Keycloak) bearer(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && k.now().Before(k.expires) {
		return k.token, nil
	}
	const op = "get the admin token"
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {k.clientID}, "client_secret": {k.clientSecret}}
	r, err := k.conn.send(ctx, op, request{
		method: http.MethodPost, url: k.base.JoinPath("realms", k.realm, "protocol", "openid-connect", "token"),
		contentType: "application/x-www-form-urlencoded", body: []byte(form.Encode()),
	})
	if err != nil {
		return "", err
	}
	if r.status == http.StatusBadRequest {
		// Keycloak answers unauthorized_client (a client that may not use the
		// grant) with 400: the credentials are not accepted either way.
		r.status = http.StatusUnauthorized
	}
	if r.status != http.StatusOK {
		return "", r.failed(ctx, op)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := decode(r, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", ErrBadResponse
	}
	k.token, k.expires = tok.AccessToken, k.now().Add(time.Duration(tok.ExpiresIn)*time.Second-tokenSkew)
	return k.token, nil
}

// forget drops the admin token, so the next request asks for a new one.
func (k *Keycloak) forget() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.token = ""
}

// do sends an Admin REST request and returns the response when its status is
// one of ok. Any other status is an *Error (404 matches ErrNotFound).
func (k *Keycloak) do(ctx context.Context, op, method string, u *url.URL, body []byte, ok ...int) (*response, error) {
	tok, err := k.bearer(ctx)
	if err != nil {
		return nil, err
	}
	rq := request{method: method, url: u, bearer: tok, body: body}
	if body != nil {
		rq.contentType = jsonType
	}
	r, err := k.conn.send(ctx, op, rq)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(ok, r.status) {
		if r.status == http.StatusUnauthorized {
			k.forget()
		}
		return nil, r.failed(ctx, op)
	}
	return r, nil
}

// Probe makes one cheap authenticated request, to tell that the realm is
// reachable and the service account is accepted.
func (k *Keycloak) Probe(ctx context.Context) error {
	u := k.admin("clients")
	u.RawQuery = url.Values{"max": {"1"}}.Encode()
	_, err := k.do(ctx, "probe the realm", http.MethodGet, u, nil, http.StatusOK)
	return err
}

// scopeRep is a client scope, or a client's assignment of one.
type scopeRep struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// scopes lists the client scopes at u (the realm's, or one client's defaults).
func (k *Keycloak) scopes(ctx context.Context, u *url.URL) ([]scopeRep, error) {
	r, err := k.do(ctx, "list client scopes", http.MethodGet, u, nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var list []scopeRep
	if err := decode(r, &list); err != nil {
		return nil, err
	}
	for _, s := range list {
		if !validID(s.ID) {
			return nil, ErrBadResponse
		}
	}
	return list, nil
}

// wantedScopes maps the names of the scopes the client is to hold to their
// ids in the realm: the spec's, and basic when the realm has it.
func (k *Keycloak) wantedScopes(ctx context.Context, s ClientSpec) (map[string]string, error) {
	realm, err := k.scopes(ctx, k.admin("client-scopes"))
	if err != nil {
		return nil, err
	}
	byName := make(map[string]string, len(realm))
	for _, r := range realm {
		byName[r.Name] = r.ID
	}
	want := map[string]string{}
	for _, n := range s.scopeNames() {
		id, ok := byName[n]
		if !ok {
			return nil, ErrUnknownScope
		}
		want[n] = id
	}
	if id, ok := byName[basicScope]; ok {
		want[basicScope] = id
	}
	return want, nil
}

// syncScopes makes the client's default client scopes the wanted ones.
func (k *Keycloak) syncScopes(ctx context.Context, id string, want map[string]string) error {
	have, err := k.scopes(ctx, k.admin("clients", id, "default-client-scopes"))
	if err != nil {
		return err
	}
	held := make(map[string]bool, len(have))
	for _, h := range have {
		held[h.Name] = true
		if _, ok := want[h.Name]; !ok {
			if _, err := k.do(ctx, "remove a client scope", http.MethodDelete,
				k.admin("clients", id, "default-client-scopes", h.ID), nil, http.StatusNoContent); err != nil {
				return err
			}
		}
	}
	for name, scopeID := range want {
		if !held[name] {
			if _, err := k.do(ctx, "add a client scope", http.MethodPut,
				k.admin("clients", id, "default-client-scopes", scopeID), nil, http.StatusNoContent); err != nil {
				return err
			}
		}
	}
	return nil
}

// fetch reads a client and refuses one whose marker is not marker.
func (k *Keycloak) fetch(ctx context.Context, id, marker string) (Client, map[string]any, error) {
	if marker == "" {
		return Client{}, nil, ErrInvalidSpec
	}
	if !validID(id) {
		return Client{}, nil, ErrInvalidID
	}
	r, err := k.do(ctx, "read the client", http.MethodGet, k.admin("clients", id), nil, http.StatusOK)
	if err != nil {
		return Client{}, nil, err
	}
	var rep representation
	if err := decode(r, &rep); err != nil {
		return Client{}, nil, err
	}
	if rep.Attributes[markerAttr] != marker {
		return Client{}, nil, ErrNameCollision
	}
	var raw map[string]any
	_ = decode(r, &raw) // the body parsed as a representation, so it parses as an object
	return Client{ID: id, ClientID: rep.ClientID, Public: rep.PublicClient, rep: rep}, raw, nil
}

// Get reads the client Keycloak calls id (its own id, kept in the claim's
// status). It returns ErrNotFound for a client that is gone and
// ErrNameCollision for one whose marker names another claim.
func (k *Keycloak) Get(ctx context.Context, id, marker string) (Client, error) {
	c, _, err := k.fetch(ctx, id, marker)
	if err != nil {
		return Client{}, err
	}
	have, err := k.scopes(ctx, k.admin("clients", id, "default-client-scopes"))
	if err != nil {
		return Client{}, err
	}
	for _, h := range have {
		c.Scopes = append(c.Scopes, h.Name)
	}
	return c, nil
}

// find returns the id of the client with the client_id, or ErrNotFound.
func (k *Keycloak) find(ctx context.Context, clientID string) (string, error) {
	u := k.admin("clients")
	u.RawQuery = url.Values{"clientId": {clientID}, "search": {"false"}}.Encode()
	r, err := k.do(ctx, "look a client up", http.MethodGet, u, nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	var list []representation
	if err := decode(r, &list); err != nil {
		return "", err
	}
	for _, c := range list {
		if c.ClientID == clientID {
			return c.ID, nil
		}
	}
	return "", ErrNotFound
}

// Create makes the client and returns it. It is idempotent: a client of that
// client_id that carries the spec's marker (one an earlier attempt made and the
// claim's status never recorded) is adopted and brought to the spec; one that
// carries another marker is ErrNameCollision. ErrUnknownScope is returned,
// before anything is made, for a scope the realm lacks.
func (k *Keycloak) Create(ctx context.Context, s ClientSpec) (Client, error) {
	if err := s.check(); err != nil {
		return Client{}, err
	}
	want, err := k.wantedScopes(ctx, s)
	if err != nil {
		return Client{}, err
	}
	r, err := k.do(ctx, "create the client", http.MethodPost, k.admin("clients"), s.body(nil),
		http.StatusCreated, http.StatusConflict)
	if err != nil {
		return Client{}, err
	}
	var id string
	if r.status == http.StatusCreated {
		id = path.Base(r.header.Get("Location"))
	} else if id, err = k.find(ctx, s.ClientID); err != nil {
		return Client{}, err
	}
	if !validID(id) {
		return Client{}, ErrBadResponse
	}
	if r.status == http.StatusConflict {
		// Update checks the marker before it changes anything.
		if err := k.Update(ctx, id, s); err != nil {
			return Client{}, err
		}
	} else if err := k.syncScopes(ctx, id, want); err != nil {
		return Client{}, err
	}
	return k.Get(ctx, id, s.Marker)
}

// Update makes the client match the spec. It refuses a client whose marker is
// not the spec's (ErrNameCollision) and keeps everything else of it.
func (k *Keycloak) Update(ctx context.Context, id string, s ClientSpec) error {
	if err := s.check(); err != nil {
		return err
	}
	want, err := k.wantedScopes(ctx, s)
	if err != nil {
		return err
	}
	_, raw, err := k.fetch(ctx, id, s.Marker)
	if err != nil {
		return err
	}
	if _, err := k.do(ctx, "update the client", http.MethodPut, k.admin("clients", id), s.body(raw),
		http.StatusNoContent); err != nil {
		return err
	}
	return k.syncScopes(ctx, id, want)
}

// Delete removes the client; one that is gone is deleted.
func (k *Keycloak) Delete(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrInvalidID
	}
	_, err := k.do(ctx, "delete the client", http.MethodDelete, k.admin("clients", id), nil, http.StatusNoContent)
	if statusOf(err) == http.StatusNotFound {
		return nil
	}
	return err
}

// credential reads or changes one of the client's secrets and returns its value.
func (k *Keycloak) credential(ctx context.Context, op, method, id string, segs ...string) (string, error) {
	if !validID(id) {
		return "", ErrInvalidID
	}
	r, err := k.do(ctx, op, method, k.admin(append([]string{"clients", id}, segs...)...), nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	var c struct {
		Value string `json:"value"`
	}
	if err := decode(r, &c); err != nil {
		return "", err
	}
	if c.Value == "" {
		return "", ErrBadResponse
	}
	return c.Value, nil
}

// Secret returns the secret of a confidential client.
func (k *Keycloak) Secret(ctx context.Context, id string) (string, error) {
	return k.credential(ctx, "read the client secret", http.MethodGet, id, "client-secret")
}

// Rotation is the outcome of a secret rotation.
type Rotation struct {
	// Secret is the client's new secret.
	Secret string
	// Overlap is true when Keycloak still accepts the previous secret (the
	// realm has a client policy with the secret-rotation executor for the
	// client), until FinishRotation or the executor's rotated-secret
	// expiration. It is false when the previous secret died at once.
	Overlap bool
}

// Rotate issues a new secret. current is the secret the binding Secret holds:
// when Keycloak's secret is no longer it, an earlier attempt rotated already
// and its result is returned instead of rotating again, which would push the
// secret consumers still hold out of Keycloak's one rotated slot. An empty
// current always rotates.
func (k *Keycloak) Rotate(ctx context.Context, id, current string) (Rotation, error) {
	secret := ""
	if current != "" {
		held, err := k.Secret(ctx, id)
		if err != nil {
			return Rotation{}, err
		}
		if subtle.ConstantTimeCompare([]byte(held), []byte(current)) != 1 {
			secret = held
		}
	}
	if secret == "" {
		var err error
		if secret, err = k.credential(ctx, "rotate the client secret", http.MethodPost, id, "client-secret"); err != nil {
			return Rotation{}, err
		}
	}
	_, err := k.credential(ctx, "read the rotated secret", http.MethodGet, id, "client-secret", "rotated")
	if statusOf(err) == http.StatusNotFound {
		return Rotation{Secret: secret}, nil
	}
	return Rotation{Secret: secret, Overlap: err == nil}, err
}

// FinishRotation invalidates the previous secret. It succeeds when there is
// none.
func (k *Keycloak) FinishRotation(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrInvalidID
	}
	_, err := k.do(ctx, "invalidate the rotated secret", http.MethodDelete,
		k.admin("clients", id, "client-secret", "rotated"), nil, http.StatusOK, http.StatusNoContent)
	if statusOf(err) == http.StatusNotFound {
		return nil
	}
	return err
}
