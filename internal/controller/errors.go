package controller

import (
	"context"
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

var (
	// ErrAdminCredentials means the admin Secret of a Keycloak provider lacks
	// clientId or clientSecret.
	ErrAdminCredentials = errors.New("the admin Secret needs the keys clientId and clientSecret")
	// ErrInitialAccessToken means initialAccessTokenSecretRef names a Secret
	// or a key that holds no token.
	ErrInitialAccessToken = errors.New("initialAccessTokenSecretRef names no token")
)

// Keys of the admin Secret of a Keycloak provider.
const (
	AdminClientIDKey     = "clientId"
	AdminClientSecretKey = "clientSecret"
)

// coarseError is what a condition and an Event show: one fixed text per kind of
// failure. The raw error (a provider's own words, an address, a Secret's name)
// is shown nowhere, not even in the log (NFR-0002); it stays reachable through
// errors.Is and errors.As for the code that decides what to do.
type coarseError struct {
	text string
	errs []error
}

func (e *coarseError) Error() string   { return e.text }
func (e *coarseError) Unwrap() []error { return e.errs }

// rule maps the errors of one kind to the text shown for them. A rule with no
// text names an error of this package, whose own text is already fixed and
// passes through unchanged.
type rule struct {
	match func(error) bool
	text  string
}

func is(target error) func(error) bool {
	return func(err error) bool { return errors.Is(err, target) }
}

// isStatus reports an HTTP answer of the provider that was not a success.
func isStatus(err error) bool {
	var e *idpclient.Error
	return errors.As(err, &e)
}

// invalidProvider is the text of every way a provider's own configuration or
// credentials are not usable.
const invalidProvider = "the provider's configuration or credentials are not usable"

// rules are tried in order.
var rules = []rule{
	{is(ErrAdminCredentials), ""},
	{is(ErrInitialAccessToken), ""},
	{is(server.ErrServerNotFound), "the referenced provider was not found"},
	{is(server.ErrNamespaceNotAllowed), "the claim's namespace is not allowed by the provider"},
	{is(server.ErrAdminSecretNamespaceForbidden), "the provider's admin credentials are not usable"},
	{is(server.ErrInvalidServer), invalidProvider},
	{is(server.ErrOperatorNamespaceUnset), invalidProvider},
	{is(server.ErrUnknownServerKind), invalidProvider},
	{is(idpclient.ErrInvalidEndpoint), invalidProvider},
	{is(idpclient.ErrInvalidRealm), invalidProvider},
	{is(idpclient.ErrInvalidCA), invalidProvider},
	{is(idpclient.ErrNoCredentials), invalidProvider},
	{is(idpclient.ErrNoDialer), invalidProvider},
	{is(egress.ErrProxy), "the connection to the provider was refused by the egress policy"},
	{is(egress.ErrProxyUserinfo), "the connection to the provider was refused by the egress policy"},
	{is(idpclient.ErrConnPolicy), "the connection to the provider was refused by the egress policy"},
	{is(idpclient.ErrConnTLS), "the TLS handshake with the provider failed"},
	{is(idpclient.ErrConnAuth), "the provider refused the operator's credentials"},
	{is(idpclient.ErrConnTimeout), "the provider did not answer in time"},
	{is(idpclient.ErrConnFailed), "the connection to the provider failed"},
	{is(idpclient.ErrBadResponse), "the provider answered with an unexpected document"},
	{isStatus, "the provider refused the request"},
}

// defaultText is shown for an error no rule knows: a failed call of the
// Kubernetes API, say.
const defaultText = "the operation failed"

// categoryOnly replaces the text of err with the fixed text of its kind. The
// raw error may hold an address. errors.Is still matches the kinds inside.
func categoryOnly(err error) error {
	if err == nil {
		return nil
	}
	for _, r := range rules {
		if r.match(err) {
			if r.text == "" {
				return err
			}
			return &coarseError{text: r.text, errs: []error{err}}
		}
	}
	return &coarseError{text: defaultText, errs: []error{err}}
}

// coarse is categoryOnly for an error that is also logged, with the operation
// it came from; the log line carries the fixed text and nothing else. An error
// that is already coarse is returned as it is, so it is logged once.
func coarse(ctx context.Context, op string, err error) error {
	var already *coarseError
	if err == nil || errors.As(err, &already) {
		return err
	}
	out := categoryOnly(err)
	log.FromContext(ctx).Error(out, "the operation failed", "operation", op)
	return out
}
