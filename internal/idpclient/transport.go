// Package idpclient holds the backend clients of operator-oidc (NR4): the
// Keycloak Admin REST client of an OidcClient's lifecycle, and the RFC 7591
// and RFC 7592 dynamic client registration client of every other provider.
//
// Both reach the provider only through the egress policy's dialer they are
// given (lib-operator-go pkg/egress), verify its certificate chain and host
// name, never follow a redirect and never read the process's proxy variables.
//
// Whatever a provider answers reaches a condition or an Event only as one of
// the fixed texts below: a tenant can aim a namespaced IdentityProvider at any
// host, so an error never carries a URL, an address, a token, a secret or the
// provider's own words. The logs carry the same categories and the HTTP status,
// nothing else.
package idpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
)

var (
	// ErrInvalidEndpoint means a provider URL is not an https URL with a host
	// and without credentials, a query or a fragment.
	ErrInvalidEndpoint = errors.New("the provider URL must be an https URL without credentials, a query or a fragment")
	// ErrInvalidRealm means the Keycloak realm is not a name of the CRD's set.
	ErrInvalidRealm = errors.New("the Keycloak realm is not a valid name")
	// ErrInvalidCA means the CA bundle holds no PEM certificate.
	ErrInvalidCA = errors.New("the CA bundle holds no PEM certificate")
	// ErrNoDialer means a Transport has no Dial: a client never falls back to
	// a dialer that skips the egress policy.
	ErrNoDialer = errors.New("a dialer is required")
	// ErrNoCredentials means a credential that is required is empty.
	ErrNoCredentials = errors.New("the credentials are empty")
	// ErrInvalidID means an id is not one of the shapes the provider assigns.
	ErrInvalidID = errors.New("the id is not valid")
	// ErrInvalidSpec means a client spec lacks its name or its ownership marker.
	ErrInvalidSpec = errors.New("the client spec is incomplete")
	// ErrNotFound is matched by an *Error whose status is 404, and returned
	// when a name that a conflict named is not there.
	ErrNotFound = errors.New("not found")
	// ErrBadResponse means the provider answered with a body that does not
	// parse or does not hold what the answer needs.
	ErrBadResponse = errors.New("the backend answered with an unexpected body")
)

// The categories of a failed request. A condition and an Event carry the error
// text to the tenant, so they carry only one of these fixed texts.
var (
	ErrConnPolicy  = errors.New("connection refused by the egress policy")
	ErrConnTLS     = errors.New("TLS handshake failed")
	ErrConnAuth    = errors.New("authentication failed")
	ErrConnTimeout = errors.New("connection timed out")
	ErrConnFailed  = errors.New("connection failed")
)

// connError is lifecycle.ErrUnreachable with a category as its text. It still
// unwraps to the cause, for errors.Is and errors.As, but Error never shows it.
type connError struct{ category, cause error }

func (e *connError) Error() string {
	return lifecycle.ErrUnreachable.Error() + ": " + e.category.Error()
}

func (e *connError) Unwrap() []error {
	return []error{lifecycle.ErrUnreachable, e.category, e.cause}
}

// Error is a non-2xx answer of a provider. Its text is the status alone: the
// body comes from a server a tenant may have chosen, so it never reaches a
// condition.
type Error struct{ Status int }

func (e *Error) Error() string { return fmt.Sprintf("the backend answered HTTP %d", e.Status) }

// Is makes errors.Is(err, ErrNotFound) true for a 404.
func (e *Error) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

// statusOf is the HTTP status behind err, or 0 when err is not an answer.
func statusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// tlsText reports whether the text of a connection error is one of
// crypto/tls's failures, or net/http's wording for a plain-HTTP answer to a
// TLS client.
func tlsText(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "tls: ") || strings.Contains(msg, "x509: ") ||
		strings.Contains(msg, "server gave http response to https client")
}

// classify maps a transport failure to its category.
func classify(err error) error {
	var verify *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.Is(err, egress.ErrBlocked):
		return ErrConnPolicy
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return ErrConnTimeout
	case errors.As(err, &verify) || tlsText(err.Error()):
		return ErrConnTLS
	}
	return ErrConnFailed
}

// Transport is how to reach and trust one provider.
type Transport struct {
	// ServerName overrides the host name used for certificate verification.
	ServerName string
	// CABundle is PEM; empty uses the system roots.
	CABundle []byte
	// MinTLS is a crypto/tls version; below TLS 1.2 is raised to 1.2.
	MinTLS uint16
	// Dial opens the TCP connection (egress.Policy.HostDialer).
	Dial egress.DialFunc
	// KeepAlive reuses connections between requests. Set it only for a client
	// that outlives a reconcile; the idle connections are bounded and closed by
	// CloseIdleConnections.
	KeepAlive bool
}

const (
	// maxIdleConns bounds the idle connections of a client to its one host.
	maxIdleConns = 4
	// maxBody bounds what is read of any answer.
	maxBody = 1 << 20
)

// conn is the HTTP client of one provider.
type conn struct{ hc *http.Client }

func newConn(t Transport) (*conn, error) {
	if t.Dial == nil {
		return nil, ErrNoDialer
	}
	cfg := &tls.Config{MinVersion: max(t.MinTLS, tls.VersionTLS12), ServerName: t.ServerName}
	if len(t.CABundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(t.CABundle) {
			return nil, ErrInvalidCA
		}
		cfg.RootCAs = pool
	}
	tr := &http.Transport{
		DialContext:           t.Dial,
		TLSClientConfig:       cfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		// Without KeepAlive a client lives for one reconcile, and idle
		// connections would leak.
		DisableKeepAlives:   !t.KeepAlive,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConns,
		IdleConnTimeout:     time.Minute,
	}
	return &conn{hc: &http.Client{
		Transport: tr,
		Timeout:   time.Minute,
		// A redirect would carry a bearer token to a host the egress policy has
		// not seen named.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// CloseIdleConnections closes the idle connections of the client.
func (c *conn) CloseIdleConnections() { c.hc.CloseIdleConnections() }

// request is one HTTP request.
type request struct {
	method, bearer, contentType, prefer string
	url                                 *url.URL
	body                                []byte
}

// response is the answer to a request.
type response struct {
	status int
	header http.Header
	body   []byte
}

// send performs rq. The error is a transport failure (a *connError); any HTTP
// status is a response.
func (c *conn) send(ctx context.Context, op string, rq request) (*response, error) {
	var body io.ReadCloser = http.NoBody
	if len(rq.body) > 0 {
		body = io.NopCloser(bytes.NewReader(rq.body))
	}
	h := http.Header{"Accept": {"application/json"}}
	if rq.contentType != "" {
		h.Set("Content-Type", rq.contentType)
	}
	if rq.bearer != "" {
		h.Set("Authorization", "Bearer "+rq.bearer)
	}
	if rq.prefer != "" {
		h.Set("Prefer", rq.prefer)
	}
	req := (&http.Request{
		Method: rq.method, URL: rq.url, Host: rq.url.Host, Header: h, Body: body, ContentLength: int64(len(rq.body)),
	}).WithContext(ctx)
	r, err := c.exchange(req)
	if err != nil {
		category := classify(err)
		log.FromContext(ctx).Info("cannot reach the backend", "operation", op, "category", category.Error())
		return nil, &connError{category: category, cause: err}
	}
	return r, nil
}

func (c *conn) exchange(req *http.Request) (*response, error) {
	resp, err := c.hc.Do(req) //nolint:gosec // G704: the destination is dialled through the egress policy, which refuses what a tenant must not reach
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return &response{status: resp.StatusCode, header: resp.Header, body: data}, err
}

// failed is the error of an unexpected status; 401 and 403 are an
// authentication failure of an unreachable provider.
func (r *response) failed(ctx context.Context, op string) error {
	log.FromContext(ctx).V(1).Info("the backend refused the request", "operation", op, "status", r.status)
	e := &Error{Status: r.status}
	if r.status == http.StatusUnauthorized || r.status == http.StatusForbidden {
		return &connError{category: ErrConnAuth, cause: e}
	}
	return e
}

// decode parses a JSON body into v.
func decode(r *response, v any) error {
	if err := json.Unmarshal(r.body, v); err != nil {
		return ErrBadResponse
	}
	return nil
}

// mustJSON marshals a value made of strings, booleans, numbers, slices and maps
// of them, which cannot fail.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// parseHTTPS parses a provider URL. The parse error is dropped: a url.Error
// would echo the URL.
func parseHTTPS(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" {
		return nil, ErrInvalidEndpoint
	}
	if u.Path == "" {
		// JoinPath of an empty path is relative, and a request line needs the
		// leading slash.
		u.Path = "/"
	}
	return u, nil
}

// idPattern is the shape of an id a provider assigns (a UUID): it lets nothing
// into a URL path that could change which object is addressed.
var idPattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)

func validID(id string) bool { return idPattern.MatchString(id) }

// sameSet reports whether two lists hold the same values, in any order.
func sameSet(a, b []string) bool {
	return setOf(a).equal(setOf(b))
}

type set map[string]struct{}

func setOf(l []string) set {
	s := make(set, len(l))
	for _, v := range l {
		s[v] = struct{}{}
	}
	return s
}

func (s set) equal(o set) bool {
	if len(s) != len(o) {
		return false
	}
	for v := range s {
		if _, ok := o[v]; !ok {
			return false
		}
	}
	return true
}

// nonNil is l, or an empty list: a JSON null would not clear a list.
func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}
