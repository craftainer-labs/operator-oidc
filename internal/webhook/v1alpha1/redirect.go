package v1alpha1

import "strings"

// A redirect URI is an exact string the identity provider will send the user
// agent, and a code or token, to. A pattern, a looser scheme or a host that
// only looks like another host turns the provider into an open redirector, so
// the rules below are strict and each has a test. They include the CEL rules of
// api/v1alpha1.RedirectURI and add what CEL cannot judge (a real URL parse, the
// host syntax and the port range), so this is the full check:
//
//   - printable ASCII only: no space, control character, non-ASCII character
//     or backslash (parsers and browsers read a backslash as a slash);
//   - no wildcard anywhere, no fragment (RFC 6749, section 3.1.2), no
//     userinfo (an "@" anywhere, so "https://good.example@evil.example" is out);
//   - the scheme is https, or http for the loopback hosts localhost and
//     127.0.0.1 only. The parsed host is compared exactly: a prefix or regex
//     match would accept http://localhost.evil.example. http://[::1] is not
//     allowed (https URIs may have any valid host, an IP address included).
//     An http URI is allowed on a public client only, the native or
//     single-page apps RFC 8252 describes; a confidential client needs https;
//   - javascript:, data:, custom schemes and relative URIs are not https or
//     http URLs with a host, so they fail the scheme rule;
//   - the host is a DNS name or an IP address, and the port is 1 to 65535.

// loopbackHosts are the only hosts an http redirect URI may have.
var loopbackHosts = []string{"localhost", "127.0.0.1"}

// RedirectURIProblem says what is wrong with a redirect or post-logout
// redirect URI of a client, or returns "" for an acceptable one. public says
// whether the client is a public one. The controller is to call it too, so a
// client that reached the cluster without admission (the webhook disabled, a
// restored backup) is refused before anything is registered with the
// provider. Until the controller exists, the CRD's CEL rules, which are looser,
// are the only check besides the webhook.
func RedirectURIProblem(raw string, public bool) string {
	if msg := plainURLProblem(raw); msg != "" {
		return msg
	}
	if strings.Contains(raw, "#") {
		return "a fragment is not allowed"
	}
	var isHTTP bool
	switch {
	case strings.HasPrefix(raw, "https://"):
	case strings.HasPrefix(raw, "http://"):
		isHTTP = true
	default:
		return "must start with https://, or with http:// for localhost or 127.0.0.1"
	}
	u, msg := parseHostURL(raw)
	if msg != "" {
		return msg
	}
	if isHTTP {
		if !isLoopback(u.Hostname()) {
			return "an http URI must have the host localhost or 127.0.0.1 exactly"
		}
		if !public {
			return "an http loopback URI is allowed only on a public client (public: true)"
		}
	}
	return ""
}

// WebOriginProblem says what is wrong with a web origin, or returns "" for an
// acceptable one: a redirect URI that is only a scheme, host and optional port
// (no path, query or trailing slash).
func WebOriginProblem(raw string, public bool) string {
	if msg := RedirectURIProblem(raw, public); msg != "" {
		return msg
	}
	u, _ := parseHostURL(raw)
	if raw != u.Scheme+"://"+u.Host {
		return "must be an origin: a scheme, a host and an optional port, without a path or a query"
	}
	return ""
}

func isLoopback(host string) bool {
	for _, h := range loopbackHosts {
		if host == h {
			return true
		}
	}
	return false
}
