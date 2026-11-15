package idpclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/craftainer-labs/lib-operator-go/pkg/dcr"
)

var (
	// ErrRegistrationLost means the provider no longer knows the registration:
	// the registration access token is refused, or the client is not there. The
	// operator never registers again by itself, since that would change the
	// client_id its workload was given (ADR 0002 section 9).
	ErrRegistrationLost = errors.New("the registration is lost")
	// ErrInvalidState means the stored registration is unusable: it lacks a
	// client id or token, or its management URI is not an https URL on the
	// provider's own host.
	ErrInvalidState = errors.New("the stored registration is not valid")
)

// DCRTarget is one provider that supports dynamic client registration.
type DCRTarget struct {
	Transport
	// RegistrationEndpoint is the https URL clients are registered at.
	RegistrationEndpoint string
	// InitialAccessToken authorises registrations (RFC 7591 section 1.2); it
	// may be empty for a provider that registers anonymously.
	InitialAccessToken string
}

// DCR registers and manages clients with RFC 7591 and RFC 7592. It is safe for
// concurrent use.
type DCR struct {
	conn     *conn
	endpoint *url.URL
	token    string
}

// NewDCR validates the target and builds its client. It makes no request.
func NewDCR(t DCRTarget) (*DCR, error) {
	endpoint, err := parseHTTPS(t.RegistrationEndpoint)
	if err != nil {
		return nil, err
	}
	c, err := newConn(t.Transport)
	if err != nil {
		return nil, err
	}
	return &DCR{conn: c, endpoint: endpoint, token: t.InitialAccessToken}, nil
}

// CloseIdleConnections closes the idle connections; the controllers call it
// when they drop a cached client.
func (d *DCR) CloseIdleConnections() { d.conn.CloseIdleConnections() }

// Registration is the client metadata the operator sets (RFC 7591 section 2),
// and, read back, what the provider holds.
type Registration struct {
	// ClientName is the client_name; the controller derives it with
	// DCRClientName.
	ClientName string
	// RedirectURIs may be empty (a client_credentials-only client).
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	GrantTypes             []string
	// TokenEndpointAuthMethod is "client_secret_basic", "client_secret_post" or
	// "none".
	TokenEndpointAuthMethod string
	Scopes                  []string
}

// metadata is the JSON of a registration request and of the answers to it.
type metadata struct {
	ClientID                string   `json:"client_id,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// metadata is the request body; clientID is empty for a registration and the
// client's id for an update, which RFC 7592 section 2.2 requires.
func (r Registration) metadata(clientID string) metadata {
	responseTypes := []string{}
	if slices.Contains(r.GrantTypes, grantAuthorizationCode) {
		responseTypes = []string{"code"}
	}
	return metadata{
		ClientID: clientID, ClientName: r.ClientName, RedirectURIs: r.RedirectURIs,
		PostLogoutRedirectURIs: r.PostLogoutRedirectURIs, GrantTypes: r.GrantTypes, ResponseTypes: responseTypes,
		TokenEndpointAuthMethod: r.TokenEndpointAuthMethod, Scope: strings.Join(r.Scopes, " "),
	}
}

func (m metadata) registration() Registration {
	return Registration{
		ClientName: m.ClientName, RedirectURIs: m.RedirectURIs, PostLogoutRedirectURIs: m.PostLogoutRedirectURIs,
		GrantTypes: m.GrantTypes, TokenEndpointAuthMethod: m.TokenEndpointAuthMethod, Scopes: strings.Fields(m.Scope),
	}
}

// Satisfies reports whether what the provider holds (r, as read back) is what
// want asks for. A provider fills in defaults, drops what it does not support
// and may leave a field out of its answer, so a field r does not carry is not
// compared, and neither is a grant type, an authentication method or a scope
// list that want leaves empty (the provider's default stands).
func (r Registration) Satisfies(want Registration) bool {
	return (r.ClientName == "" || r.ClientName == want.ClientName) &&
		(r.TokenEndpointAuthMethod == "" || want.TokenEndpointAuthMethod == "" || r.TokenEndpointAuthMethod == want.TokenEndpointAuthMethod) &&
		(len(r.RedirectURIs) == 0 || sameSet(r.RedirectURIs, want.RedirectURIs)) &&
		(len(r.PostLogoutRedirectURIs) == 0 || sameSet(r.PostLogoutRedirectURIs, want.PostLogoutRedirectURIs)) &&
		(len(r.GrantTypes) == 0 || len(want.GrantTypes) == 0 || sameSet(r.GrantTypes, want.GrantTypes)) &&
		(len(r.Scopes) == 0 || len(want.Scopes) == 0 || sameSet(r.Scopes, want.Scopes))
}

// Info is what the provider answered about a registered client.
type Info struct {
	// State is what must be stored (dcr.Store.Write) after every call that
	// returns it: the registration access token may have changed (RFC 7592
	// lets the provider issue a new one with any answer).
	State dcr.State
	// Secret is the client's secret when the answer carried one: always after a
	// registration, and after an update or a read only when the provider
	// issued a new one. Empty means unchanged, or a public client.
	Secret string
	// SecretExpiresAt is when Secret expires; zero means never.
	SecretExpiresAt time.Time
	// Registration is the metadata the provider holds.
	Registration Registration
}

// registrationAnswer is the JSON of a client information response (RFC 7592
// section 3).
type registrationAnswer struct {
	metadata
	ClientSecret            string `json:"client_secret"`
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at"`
	RegistrationAccessToken string `json:"registration_access_token"`
	RegistrationClientURI   string `json:"registration_client_uri"`
}

// sameOrigin reports whether b is on the scheme, host and port of a.
func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		return "443"
	}
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// manageURL checks the management URI of a registration. The provider chose it
// and it is stored in a Secret, and the registration access token is sent to
// it, so it must be an https URL on the registration endpoint's own origin and
// carry no credentials: the token is never sent elsewhere.
func (d *DCR) manageURL(raw string) (*url.URL, error) {
	u, err := parseHTTPS(raw)
	if err != nil || !sameOrigin(d.endpoint, u) {
		return nil, ErrInvalidState
	}
	return u, nil
}

// info reads an answer. prev is the registration the answer is about (zero for
// a registration); what the answer leaves out is kept from it.
func (d *DCR) info(r *response, prev dcr.State) (Info, error) {
	var a registrationAnswer
	if err := decode(r, &a); err != nil {
		return Info{}, err
	}
	st := prev
	if a.ClientID != "" {
		if prev.ClientID != "" && a.ClientID != prev.ClientID {
			return Info{}, ErrBadResponse
		}
		st.ClientID = a.ClientID
	}
	if a.RegistrationAccessToken != "" {
		st.RegistrationAccessToken = a.RegistrationAccessToken
	}
	if a.RegistrationClientURI != "" {
		st.RegistrationClientURI = a.RegistrationClientURI
	}
	if _, err := d.manageURL(st.RegistrationClientURI); err != nil || st.ClientID == "" || st.RegistrationAccessToken == "" {
		return Info{}, ErrBadResponse
	}
	out := Info{State: st, Secret: a.ClientSecret, Registration: a.registration()}
	if a.ClientSecretExpiresAt > 0 {
		out.SecretExpiresAt = time.Unix(a.ClientSecretExpiresAt, 0)
	}
	return out, nil
}

// Register registers a new client. The answer's State holds the client_id, the
// management URI and the registration access token: store it before anything
// else, it is the only way to manage the client. A rotation of the secret is a
// second Register and a Delete of the first registration (RFC 7591 and 7592
// define no other), so the client_id changes with it.
func (d *DCR) Register(ctx context.Context, reg Registration) (Info, error) {
	const op = "register the client"
	r, err := d.conn.send(ctx, op, request{
		method: http.MethodPost, url: d.endpoint, bearer: d.token, contentType: jsonType, body: mustJSON(reg.metadata("")),
	})
	if err != nil {
		return Info{}, err
	}
	if r.status != http.StatusCreated && r.status != http.StatusOK {
		return Info{}, r.failed(ctx, op)
	}
	return d.info(r, dcr.State{})
}

// manage sends a request to the management URI of a registration, with its
// token. It returns the response for any status.
func (d *DCR) manage(ctx context.Context, op, method string, st dcr.State, body []byte) (*response, error) {
	u, err := d.manageURL(st.RegistrationClientURI)
	if err != nil || st.ClientID == "" || st.RegistrationAccessToken == "" {
		return nil, ErrInvalidState
	}
	rq := request{method: method, url: u, bearer: st.RegistrationAccessToken, body: body}
	if body != nil {
		rq.contentType = jsonType
	}
	return d.conn.send(ctx, op, rq)
}

// lost reports a status that means the provider no longer honours the
// registration.
func lost(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound
}

// Get reads the registered client by its stored registration. It returns
// ErrRegistrationLost when the provider no longer knows it.
func (d *DCR) Get(ctx context.Context, st dcr.State) (Info, error) {
	const op = "read the registration"
	r, err := d.manage(ctx, op, http.MethodGet, st, nil)
	if err != nil {
		return Info{}, err
	}
	if lost(r.status) {
		return Info{}, ErrRegistrationLost
	}
	if r.status != http.StatusOK {
		return Info{}, r.failed(ctx, op)
	}
	return d.info(r, st)
}

// Update replaces the client's metadata. Store the answer's State: the provider
// may have issued a new registration access token.
func (d *DCR) Update(ctx context.Context, st dcr.State, reg Registration) (Info, error) {
	const op = "update the registration"
	r, err := d.manage(ctx, op, http.MethodPut, st, mustJSON(reg.metadata(st.ClientID)))
	if err != nil {
		return Info{}, err
	}
	if lost(r.status) {
		return Info{}, ErrRegistrationLost
	}
	if r.status != http.StatusOK {
		return Info{}, r.failed(ctx, op)
	}
	return d.info(r, st)
}

// Delete removes the registered client. A client that is gone is deleted; a
// refused token is ErrRegistrationLost.
func (d *DCR) Delete(ctx context.Context, st dcr.State) error {
	const op = "delete the registration"
	r, err := d.manage(ctx, op, http.MethodDelete, st, nil)
	if err != nil {
		return err
	}
	switch r.status {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrRegistrationLost
	}
	return r.failed(ctx, op)
}
