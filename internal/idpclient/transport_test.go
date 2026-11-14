package idpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"
)

// probeOf starts handler h over TLS and returns a Keycloak client of it, with
// the transport tr edited by edit.
func probeOf(t *testing.T, h http.Handler, edit func(*Transport)) (*Keycloak, *httptest.Server) {
	t.Helper()
	srv, tr := startTLS(t, h)
	if edit != nil {
		edit(&tr)
	}
	k, err := NewKeycloak(KeycloakTarget{Transport: tr, BaseURL: srv.URL, Realm: "test", ClientID: "operator", ClientSecret: "operator-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return k, srv
}

// TestTransportCategories checks that every way a request can fail before an
// answer is one category, reaches the caller as lifecycle.ErrUnreachable, and
// says nothing of the address, the name or the raw error.
func TestTransportCategories(t *testing.T) {
	ok := newFakeKeycloak()
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	short := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{"))
	})
	slow := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-block:
		case <-time.After(3 * time.Second):
		}
	})
	plain := httptest.NewServer(ok)
	t.Cleanup(plain.Close)
	oldTLS := httptest.NewUnstartedServer(ok)
	oldTLS.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12} //nolint:gosec // a server limited to TLS 1.2 on purpose
	oldTLS.StartTLS()
	t.Cleanup(oldTLS.Close)

	for _, tc := range []struct {
		name string
		run  func(t *testing.T) error
		want error
	}{
		{"the egress policy", func(t *testing.T) error {
			k, _ := probeOf(t, ok, func(tr *Transport) {
				d, err := egress.NewPolicy(egress.ModeStrict).HostDialer(nil)
				if err != nil {
					t.Fatal(err)
				}
				tr.Dial = d
			})
			return k.Probe(t.Context())
		}, ErrConnPolicy},
		{"an untrusted certificate", func(t *testing.T) error {
			k, _ := probeOf(t, ok, func(tr *Transport) { tr.CABundle = nil })
			return k.Probe(t.Context())
		}, ErrConnTLS},
		{"a wrong name", func(t *testing.T) error {
			k, _ := probeOf(t, ok, func(tr *Transport) { tr.ServerName = "other.example.org" })
			return k.Probe(t.Context())
		}, ErrConnTLS},
		{"a TLS floor above the server's", func(t *testing.T) error {
			tr := Transport{CABundle: pemOf(oldTLS), Dial: direct, MinTLS: tls.VersionTLS13}
			k, err := NewKeycloak(KeycloakTarget{Transport: tr, BaseURL: oldTLS.URL, Realm: "test", ClientID: "o", ClientSecret: "s"})
			if err != nil {
				t.Fatal(err)
			}
			return k.Probe(t.Context())
		}, ErrConnTLS},
		{"a plain server", func(t *testing.T) error {
			tr := Transport{Dial: direct}
			k, err := NewKeycloak(KeycloakTarget{
				Transport: tr, BaseURL: strings.Replace(plain.URL, "http://", "https://", 1), Realm: "test", ClientID: "o", ClientSecret: "s",
			})
			if err != nil {
				t.Fatal(err)
			}
			return k.Probe(t.Context())
		}, ErrConnTLS},
		{"a server that is gone", func(t *testing.T) error {
			k, srv := probeOf(t, ok, nil)
			srv.Close()
			return k.Probe(t.Context())
		}, ErrConnFailed},
		{"an answer that stops short", func(t *testing.T) error {
			k, _ := probeOf(t, short, nil)
			return k.Probe(t.Context())
		}, ErrConnFailed},
		{"a deadline", func(t *testing.T) error {
			k, _ := probeOf(t, slow, nil)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			return k.Probe(ctx)
		}, ErrConnTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if !errors.Is(err, tc.want) || !errors.Is(err, lifecycle.ErrUnreachable) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
			if got, want := err.Error(), lifecycle.ErrUnreachable.Error()+": "+tc.want.Error(); got != want {
				t.Fatalf("the error says %q, want %q", got, want)
			}
		})
	}
}

func TestTransportOptions(t *testing.T) {
	ctx := t.Context()
	f := newFakeKeycloak()
	// The test server's certificate is for example.com and the loopback
	// addresses: a name override that matches it works, and TLS 1.3 and
	// keep-alive are fine.
	k, _ := probeOf(t, f, func(tr *Transport) {
		tr.ServerName, tr.MinTLS, tr.KeepAlive = "example.com", tls.VersionTLS13, true
	})
	for range 2 {
		if err := k.Probe(ctx); err != nil {
			t.Fatal(err)
		}
	}
	k.CloseIdleConnections()
}

// TestRedirectsAreNotFollowed checks that a redirect, which would carry the
// bearer token to a host the egress policy has not seen named, is an error.
func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits atomic.Int32
	other, _ := startTLS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	f := newFakeKeycloak()
	f.rules = []rule{{"GET", "/clients", reply{status: 302, header: map[string]string{"Location": other.URL}}}}
	k, _ := probeOf(t, f, nil)
	err := k.Probe(t.Context())
	if statusOf(err) != 302 || hits.Load() != 0 {
		t.Fatalf("%v, %d hits", err, hits.Load())
	}
}

func TestNewConn(t *testing.T) {
	if _, err := newConn(Transport{}); !errors.Is(err, ErrNoDialer) {
		t.Fatalf("%v", err)
	}
	if _, err := newConn(Transport{Dial: direct, CABundle: []byte("junk")}); !errors.Is(err, ErrInvalidCA) {
		t.Fatalf("%v", err)
	}
}

func TestErrorText(t *testing.T) {
	e := &Error{Status: 404}
	if e.Error() != "the backend answered HTTP 404" || !errors.Is(e, ErrNotFound) || errors.Is(&Error{Status: 500}, ErrNotFound) {
		t.Fatal(e)
	}
	if statusOf(errors.New("x")) != 0 || statusOf(nil) != 0 {
		t.Fatal("statusOf")
	}
}

func TestSets(t *testing.T) {
	if !sameSet(nil, []string{}) || !sameSet([]string{"a", "b", "a"}, []string{"b", "a"}) {
		t.Fatal("equal sets differ")
	}
	if sameSet([]string{"a"}, []string{"a", "b"}) || sameSet([]string{"a", "c"}, []string{"a", "b"}) {
		t.Fatal("different sets are equal")
	}
	if nonNil(nil) == nil || len(nonNil([]string{"x"})) != 1 {
		t.Fatal("nonNil")
	}
}
