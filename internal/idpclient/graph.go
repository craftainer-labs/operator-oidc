package idpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Microsoft Graph (v1.0) application registrations, over net/http: five stable
// calls (create, update and delete an application, addPassword and
// removePassword) do not justify a generated model of all of Graph. The access
// token comes from the caller (azidentity through lib-operator-go's
// cloud.Egress.Azure), and the HTTP client is the egress policy's.

// GraphBase is the Microsoft Graph host of the public cloud.
const GraphBase = "https://graph.microsoft.com"

// GraphScope is the scope of a Graph access token.
const GraphScope = GraphBase + "/.default"

// GraphAudience is the signInAudience of every application the operator
// makes: the tenant's own accounts only.
const GraphAudience = "AzureADMyOrg"

// ErrGraphToken means the access token for Graph could not be fetched.
var ErrGraphToken = errors.New("the Graph access token could not be fetched")

// guid is the shape of the object IDs, application IDs and key IDs Graph
// assigns. An ID is a path segment of a request, so nothing else is let through.
var guid = regexp.MustCompile(`^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`)

// GraphToken returns an access token for Microsoft Graph.
type GraphToken func(ctx context.Context) (string, error)

// GraphPassword is a client secret of an application: its key ID and name. Its
// value is never readable after it was issued.
type GraphPassword struct {
	KeyID       string
	DisplayName string
}

// GraphApp is an application registration, as far as the operator manages it.
type GraphApp struct {
	// ID is the object ID, AppID the application (client) ID.
	ID    string
	AppID string
	// DisplayName is the name of the registration.
	DisplayName string
	// Audience is the signInAudience.
	Audience string
	// Public is isFallbackPublicClient: the application is a public client.
	Public bool
	// WebRedirectURIs and PublicRedirectURIs are the redirect URIs of the web
	// and the public client platform.
	WebRedirectURIs    []string
	PublicRedirectURIs []string
	// LogoutURL is web.logoutUrl, "" for none.
	LogoutURL string
	// Passwords are the client secrets.
	Passwords []GraphPassword
}

// GraphSecret is a client secret just issued by addPassword.
type GraphSecret struct {
	KeyID string
	Value string
}

// Graph is the Microsoft Graph client of one tenant.
type Graph struct {
	*conn
	base  *url.URL
	token GraphToken
}

// NewGraph returns the client of the Graph at base (GraphBase, or an
// endpointOverride); hc dials through the egress policy.
func NewGraph(hc *http.Client, base string, token GraphToken) (*Graph, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, ErrInvalidEndpoint
	}
	if hc == nil || token == nil {
		return nil, ErrNoCredentials
	}
	// An explicit slash: JoinPath of a URL with no path would give a relative one.
	b := *u
	b.Path, b.RawPath = strings.TrimSuffix(u.Path, "/")+"/v1.0", ""
	return &Graph{conn: &conn{hc: hc}, base: &b, token: token}, nil
}

// do sends a request to the path below v1.0 and returns the answer when its
// status is one of ok; any other status is an *Error.
func (g *Graph) do(ctx context.Context, op, method string, query url.Values, body any, ok []int, segments ...string) (*response, error) {
	tok, err := g.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGraphToken, err)
	}
	u := g.base.JoinPath(segments...)
	if query != nil {
		u.RawQuery = query.Encode()
	}
	rq := request{method: method, url: u, bearer: tok}
	if body != nil {
		rq.body = mustJSON(body)
		rq.contentType = jsonType
	}
	r, err := g.send(ctx, op, rq)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(ok, r.status) {
		return nil, r.failed(ctx, op)
	}
	return r, nil
}

// Probe makes one cheap authenticated request that needs only the permission
// the operator has anyway (Application.ReadWrite.OwnedBy): it lists at most one
// application the identity owns.
func (g *Graph) Probe(ctx context.Context) error {
	_, err := g.do(ctx, "probe the tenant", http.MethodGet, url.Values{"$top": {"1"}, "$select": {"id"}}, nil,
		[]int{http.StatusOK}, "applications")
	return err
}

type graphPlatform struct {
	RedirectURIs []string `json:"redirectUris"`
}

type graphWeb struct {
	RedirectURIs []string `json:"redirectUris"`
	// LogoutURL is null when there is none, which clears it on a PATCH.
	LogoutURL *string `json:"logoutUrl"`
}

type graphApp struct {
	ID                     string            `json:"id,omitempty"`
	AppID                  string            `json:"appId,omitempty"`
	DisplayName            string            `json:"displayName,omitempty"`
	SignInAudience         string            `json:"signInAudience,omitempty"`
	IsFallbackPublicClient bool              `json:"isFallbackPublicClient"`
	Web                    graphWeb          `json:"web"`
	PublicClient           graphPlatform     `json:"publicClient"`
	PasswordCredentials    []graphCredential `json:"passwordCredentials,omitempty"`
}

type graphCredential struct {
	KeyID       string `json:"keyId"`
	DisplayName string `json:"displayName"`
}

// strs is s, never nil: Graph clears a list it is given empty, and a null
// list is not the same as an empty one.
func strs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a GraphApp) wire() graphApp {
	w := graphApp{
		DisplayName: a.DisplayName, SignInAudience: a.Audience, IsFallbackPublicClient: a.Public,
		Web: graphWeb{RedirectURIs: strs(a.WebRedirectURIs)}, PublicClient: graphPlatform{RedirectURIs: strs(a.PublicRedirectURIs)},
	}
	if a.LogoutURL != "" {
		u := a.LogoutURL
		w.Web.LogoutURL = &u
	}
	return w
}

func (w graphApp) app() (GraphApp, error) {
	if !guid.MatchString(w.ID) || !guid.MatchString(w.AppID) {
		return GraphApp{}, ErrBadResponse
	}
	a := GraphApp{
		ID: w.ID, AppID: w.AppID, DisplayName: w.DisplayName, Audience: w.SignInAudience, Public: w.IsFallbackPublicClient,
		WebRedirectURIs: w.Web.RedirectURIs, PublicRedirectURIs: w.PublicClient.RedirectURIs,
	}
	if w.Web.LogoutURL != nil {
		a.LogoutURL = *w.Web.LogoutURL
	}
	for _, c := range w.PasswordCredentials {
		if !guid.MatchString(c.KeyID) {
			return GraphApp{}, ErrBadResponse
		}
		a.Passwords = append(a.Passwords, GraphPassword(c))
	}
	return a, nil
}

func (g *Graph) decodeApp(r *response) (GraphApp, error) {
	var w graphApp
	if err := decode(r, &w); err != nil {
		return GraphApp{}, err
	}
	return w.app()
}

// Create makes the application. ID and Passwords of a are ignored.
func (g *Graph) Create(ctx context.Context, a GraphApp) (GraphApp, error) {
	r, err := g.do(ctx, "create the application", http.MethodPost, nil, a.wire(), []int{http.StatusCreated}, "applications")
	if err != nil {
		return GraphApp{}, err
	}
	return g.decodeApp(r)
}

// Get reads the application by its object ID; a missing one is ErrNotFound.
func (g *Graph) Get(ctx context.Context, id string) (GraphApp, error) {
	if !guid.MatchString(id) {
		return GraphApp{}, ErrInvalidID
	}
	r, err := g.do(ctx, "read the application", http.MethodGet, nil, nil, []int{http.StatusOK}, "applications", id)
	if err != nil {
		return GraphApp{}, err
	}
	return g.decodeApp(r)
}

// Update sets the application's settings to a (PATCH). The name, the audience,
// both platforms' redirect URIs and the logout URL are sent whole, so a value
// someone added behind the operator's back is removed.
func (g *Graph) Update(ctx context.Context, id string, a GraphApp) error {
	if !guid.MatchString(id) {
		return ErrInvalidID
	}
	_, err := g.do(ctx, "update the application", http.MethodPatch, nil, a.wire(), []int{http.StatusNoContent, http.StatusOK},
		"applications", id)
	return err
}

// Delete deletes the application; a missing one is ErrNotFound.
func (g *Graph) Delete(ctx context.Context, id string) error {
	if !guid.MatchString(id) {
		return ErrInvalidID
	}
	_, err := g.do(ctx, "delete the application", http.MethodDelete, nil, nil, []int{http.StatusNoContent}, "applications", id)
	return err
}

// AddPassword issues a client secret named name, next to the ones the
// application has.
func (g *Graph) AddPassword(ctx context.Context, id, name string) (GraphSecret, error) {
	if !guid.MatchString(id) {
		return GraphSecret{}, ErrInvalidID
	}
	body := map[string]any{"passwordCredential": map[string]string{"displayName": name}}
	r, err := g.do(ctx, "add a client secret", http.MethodPost, nil, body, []int{http.StatusOK}, "applications", id, "addPassword")
	if err != nil {
		return GraphSecret{}, err
	}
	var rep struct {
		KeyID      string `json:"keyId"`
		SecretText string `json:"secretText"`
	}
	if err := decode(r, &rep); err != nil {
		return GraphSecret{}, err
	}
	if !guid.MatchString(rep.KeyID) || rep.SecretText == "" {
		return GraphSecret{}, ErrBadResponse
	}
	return GraphSecret{KeyID: rep.KeyID, Value: rep.SecretText}, nil
}

// RemovePassword removes the client secret with keyID. A secret that is already
// gone is not an error.
func (g *Graph) RemovePassword(ctx context.Context, id, keyID string) error {
	if !guid.MatchString(id) || !guid.MatchString(keyID) {
		return ErrInvalidID
	}
	_, err := g.do(ctx, "remove a client secret", http.MethodPost, nil, map[string]string{"keyId": keyID},
		[]int{http.StatusNoContent}, "applications", id, "removePassword")
	if err == nil {
		return nil
	}
	// Graph answers 400 for a key ID the application does not hold: it is gone
	// if the application no longer lists it.
	var e *Error
	if errors.As(err, &e) && (e.Status == http.StatusBadRequest || e.Status == http.StatusNotFound) {
		if app, gerr := g.Get(ctx, id); gerr == nil && !slices.ContainsFunc(app.Passwords, func(p GraphPassword) bool { return p.KeyID == keyID }) {
			return nil
		}
	}
	return err
}
