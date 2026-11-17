package controller

import (
	"context"
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
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
	// ErrInvalidClient means the OidcClient's spec breaks a rule the CRD and
	// the webhook enforce too (the controller checks again, so a claim that
	// reached the cluster without admission is refused before anything is made
	// at the provider).
	ErrInvalidClient = errors.New("the client's spec is not valid")
	// ErrScopeNotAllowed means a scope of the client is not in the provider's
	// allowedScopes.
	ErrScopeNotAllowed = errors.New("a scope of the client is not allowed by the provider")
	// ErrBindingNotUsable means the binding Secret does not hold the client's
	// secret, which the provider will not tell again: the next reconcile finds
	// the Secret missing and issues a new one through a rotation.
	ErrBindingNotUsable = errors.New("the binding Secret does not hold the client's secret")
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

// isCloudError reports a failure of the cloud API or of the cloud credentials,
// whose text is already one of a few fixed categories (*CloudError).
func isCloudError(err error) bool {
	var e *CloudError
	return errors.As(err, &e)
}

// isStatus reports an HTTP answer of the provider that was not a success.
func isStatus(err error) bool {
	var e *idpclient.Error
	return errors.As(err, &e)
}

// invalidProvider is the text of every way a provider's own configuration or
// credentials are not usable.
const invalidProvider = "the provider's configuration or credentials are not usable"

// invalidClient is the text of a client the operator cannot send to the
// provider.
const invalidClient = "the client cannot be sent to the provider"

// egressRefused is the text of every way the egress policy, or a proxy it
// checks, refuses a connection.
const egressRefused = "the connection to the provider was refused by the egress policy"

// rules are tried in order.
var rules = []rule{
	{is(ErrAdminCredentials), ""},
	{is(ErrInitialAccessToken), ""},
	{is(ErrInvalidClient), ""},
	{is(ErrScopeNotAllowed), ""},
	{is(ErrBindingNotUsable), ""},
	{is(ErrCognitoSecret), ""},
	{isCloudError, ""},
	{is(server.ErrCredentialsSecretNamespaceForbidden), invalidProvider},
	{is(server.ErrCredentialsUnavailable), invalidProvider},
	{is(lifecycle.ErrNameCollision), "a client of that name exists and this claim did not make it"},
	{is(idpclient.ErrUnknownScope), "a scope of the client is not a client scope of the provider's realm"},
	{is(idpclient.ErrRegistrationLost), "the provider no longer holds the client's registration"},
	{is(idpclient.ErrInvalidState), "the stored registration is not valid"},
	{is(idpclient.ErrInvalidSpec), invalidClient},
	{is(idpclient.ErrInvalidID), invalidClient},
	{is(server.ErrServerNotFound), "the referenced provider was not found"},
	{is(server.ErrNamespaceNotAllowed), "the claim's namespace is not allowed by the provider"},
	{is(server.ErrAdminSecretNamespaceForbidden), "the provider's admin credentials are not usable"},
	// The egress rules come before ErrInvalidServer: a proxy the policy refuses
	// reaches here wrapped in it, and the more specific text is the true one.
	{is(egress.ErrProxy), egressRefused},
	{is(egress.ErrProxyUserinfo), egressRefused},
	{is(server.ErrInvalidServer), invalidProvider},
	{is(server.ErrOperatorNamespaceUnset), invalidProvider},
	{is(server.ErrUnknownServerKind), invalidProvider},
	{is(idpclient.ErrInvalidEndpoint), invalidProvider},
	{is(idpclient.ErrInvalidRealm), invalidProvider},
	{is(idpclient.ErrInvalidCA), invalidProvider},
	{is(idpclient.ErrNoCredentials), invalidProvider},
	{is(idpclient.ErrNoDialer), invalidProvider},
	{is(idpclient.ErrConnPolicy), egressRefused},
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
			return &coarseError{text: r.text, errs: withReach(err)}
		}
	}
	return &coarseError{text: defaultText, errs: withReach(err)}
}

// withReach returns the errors a coarseError holds for err: err itself, and
// lifecycle.ErrUnreachable when the provider could not be reached, so a claim
// shows ServerReachable=False instead of a generic failure.
func withReach(err error) []error {
	for _, target := range []error{idpclient.ErrConnPolicy, idpclient.ErrConnTLS, idpclient.ErrConnTimeout, idpclient.ErrConnFailed} {
		if errors.Is(err, target) {
			return []error{err, lifecycle.ErrUnreachable}
		}
	}
	return []error{err}
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
