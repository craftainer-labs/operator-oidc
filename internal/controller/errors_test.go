package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
)

// Every kind of failure shows one fixed text, whatever the raw error says, and
// the raw error stays reachable for the code that decides what to do.
func TestCategoryOnly(t *testing.T) {
	raw := "https://secret.internal:8443/realms/x token=abc"
	cases := []struct {
		err  error
		text string
	}{
		{server.ErrServerNotFound, "the referenced provider was not found"},
		{server.ErrNamespaceNotAllowed, "the claim's namespace is not allowed by the provider"},
		{server.ErrAdminSecretNamespaceForbidden, "the provider's admin credentials are not usable"},
		{server.ErrInvalidServer, invalidProvider},
		{server.ErrOperatorNamespaceUnset, invalidProvider},
		{server.ErrUnknownServerKind, invalidProvider},
		{idpclient.ErrInvalidEndpoint, invalidProvider},
		{idpclient.ErrInvalidRealm, invalidProvider},
		{idpclient.ErrInvalidCA, invalidProvider},
		{idpclient.ErrNoCredentials, invalidProvider},
		{idpclient.ErrNoDialer, invalidProvider},
		{egress.ErrProxy, "the connection to the provider was refused by the egress policy"},
		{egress.ErrProxyUserinfo, "the connection to the provider was refused by the egress policy"},
		{idpclient.ErrConnPolicy, "the connection to the provider was refused by the egress policy"},
		{idpclient.ErrConnTLS, "the TLS handshake with the provider failed"},
		{idpclient.ErrConnAuth, "the provider refused the operator's credentials"},
		{idpclient.ErrConnTimeout, "the provider did not answer in time"},
		{idpclient.ErrConnFailed, "the connection to the provider failed"},
		{idpclient.ErrBadResponse, "the provider answered with an unexpected document"},
		{&idpclient.Error{Status: 500}, "the provider refused the request"},
		{errors.New(raw), defaultText},
	}
	for _, c := range cases {
		wrapped := fmt.Errorf("%s: %w", raw, c.err)
		got := categoryOnly(wrapped)
		if got.Error() != c.text {
			t.Errorf("%v: text = %q, want %q", c.err, got.Error(), c.text)
		}
		if !errors.Is(got, c.err) && !errors.Is(got, wrapped) {
			t.Errorf("%v: the kind is no longer reachable", c.err)
		}
	}
	// An error of this package already has a fixed text and passes through.
	for _, own := range []error{ErrAdminCredentials, ErrInitialAccessToken} {
		if got := categoryOnly(own); !errors.Is(got, own) || got.Error() != own.Error() {
			t.Errorf("%v was changed to %v", own, got)
		}
	}
	if categoryOnly(nil) != nil {
		t.Error("nil became an error")
	}
}

func TestCoarseLogsOnceAndKeepsTheKind(t *testing.T) {
	ctx := context.Background()
	if coarse(ctx, "op", nil) != nil {
		t.Error("nil became an error")
	}
	first := coarse(ctx, "op", fmt.Errorf("https://x.example: %w", idpclient.ErrConnTLS))
	if first.Error() != "the TLS handshake with the provider failed" || !errors.Is(first, idpclient.ErrConnTLS) {
		t.Errorf("first = %v", first)
	}
	if again := coarse(ctx, "other", first); !errors.Is(again, first) || again.Error() != first.Error() {
		t.Errorf("a coarse error was changed to %v", again)
	}
}
