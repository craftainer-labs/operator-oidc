package v1alpha1

import (
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

// redirectCases are the redirect URI rules. A rejected case names a substring
// of the message. Every rule that keeps a redirect URI from becoming an open
// redirect has a case here, and the same URIs are sent through the API server
// in crd_rules_test.go so the CEL rules agree.
var redirectCases = []struct {
	name    string
	uri     string
	public  bool
	message string // empty means the URI is accepted
}{
	{name: "https", uri: "https://app.example.com/callback"},
	{name: "https with a port and a query", uri: "https://app.example.com:8443/cb?tenant=a"},
	{name: "https on an IP address", uri: "https://10.0.0.7/cb"},
	{name: "https on an IPv6 address", uri: "https://[fd00::7]:8443/cb"},
	{name: "https on localhost", uri: "https://localhost/cb"},
	{name: "https with a trailing dot", uri: "https://app.example.com./cb"},
	{name: "https with the maximum port", uri: "https://app.example.com:65535/cb"},
	{name: "http localhost on a public client", uri: "http://localhost:8080/cb", public: true},
	{name: "http 127.0.0.1 on a public client", uri: "http://127.0.0.1:8080/cb", public: true},
	{name: "http localhost without a port", uri: "http://localhost/cb", public: true},

	{name: "http loopback on a confidential client", uri: "http://localhost:8080/cb", message: "only on a public client"},
	{name: "http 127.0.0.1 on a confidential client", uri: "http://127.0.0.1/cb", message: "only on a public client"},
	{name: "http on another host", uri: "http://app.example.com/cb", public: true, message: "localhost or 127.0.0.1 exactly"},
	{name: "http host that starts with localhost", uri: "http://localhost.evil.example/cb", public: true, message: "localhost or 127.0.0.1 exactly"},
	{name: "http host that ends with localhost", uri: "http://evil-localhost/cb", public: true, message: "localhost or 127.0.0.1 exactly"},
	{name: "http host that starts with the loopback address", uri: "http://127.0.0.1.evil.example/cb", public: true, message: "localhost or 127.0.0.1 exactly"},
	{name: "http short loopback form", uri: "http://127.1/cb", public: true, message: "host name or an IP address"},
	{name: "https leading-zero IPv4", uri: "https://010.0.0.1/cb", message: "host name or an IP address"},
	{name: "https upper-case hex IP", uri: "https://0X7F.1/cb", message: "host name or an IP address"},
	{name: "https bare hex label", uri: "https://app.0x/cb", message: "host name or an IP address"},
	{name: "https IPv4 with a trailing dot", uri: "https://127.0.0.1./cb", message: "host name or an IP address"},
	{name: "http decimal loopback", uri: "http://2130706433/cb", public: true, message: "host name or an IP address"},
	{name: "http hex loopback", uri: "http://0x7f.1/cb", public: true, message: "host name or an IP address"},
	{name: "https decimal IP", uri: "https://2130706433/cb", message: "host name or an IP address"},
	{name: "https short IP", uri: "https://127.1/cb", message: "host name or an IP address"},
	{name: "https hex IP", uri: "https://0x7f.0.0.1/cb", message: "host name or an IP address"},
	{name: "https numeric last label", uri: "https://app.example.123/cb", message: "host name or an IP address"},
	{name: "https numeric single label with a dot", uri: "https://2130706433./cb", message: "host name or an IP address"},
	{name: "http IPv6 loopback", uri: "http://[::1]:8080/cb", public: true, message: "localhost or 127.0.0.1 exactly"},
	{name: "http upper case host", uri: "http://LOCALHOST/cb", public: true, message: "localhost or 127.0.0.1 exactly"},
	{name: "http loopback port zero", uri: "http://localhost:0/cb", public: true, message: "port must be between 1 and 65535"},

	{name: "javascript", uri: "javascript:alert(1)", public: true, message: "must start with https://"},
	{name: "javascript with a host look-alike", uri: "javascript://example.com/%0aalert(1)", public: true, message: "must start with https://"},
	{name: "data", uri: "data:text/html,hi", public: true, message: "must start with https://"},
	{name: "custom scheme", uri: "com.example.app:/callback", public: true, message: "must start with https://"},
	{name: "ftp", uri: "ftp://example.com/x", message: "must start with https://"},
	{name: "scheme-relative", uri: "//evil.example/cb", message: "must start with https://"},
	{name: "relative", uri: "/callback", message: "must start with https://"},
	{name: "upper-case scheme", uri: "HTTPS://app.example.com/cb", message: "must start with https://"},
	{name: "leading space", uri: " https://app.example.com/cb", message: "printable ASCII"},
	{name: "trailing newline", uri: "https://app.example.com/cb\n", message: "printable ASCII"},
	{name: "tab in the path", uri: "https://app.example.com/c\tb", message: "printable ASCII"},
	{name: "carriage return", uri: "https://app.example.com/cb\r\nLocation: https://evil.example", message: "printable ASCII"},
	{name: "NUL", uri: "https://app.example.com/\x00", message: "printable ASCII"},
	{name: "non-ASCII host", uri: "https://аpp.example.com/cb", message: "printable ASCII"},
	{name: "backslash before the userinfo", uri: `https://evil.example\@good.example/cb`, message: "printable ASCII"},
	{name: "backslash path", uri: `https://good.example\.evil.example/cb`, message: "printable ASCII"},

	{name: "wildcard host", uri: "https://*.example.com/cb", message: "wildcards"},
	{name: "wildcard path", uri: "https://app.example.com/*", message: "wildcards"},
	{name: "wildcard query", uri: "https://app.example.com/cb?x=*", message: "wildcards"},
	{name: "wildcard host on loopback", uri: "http://*/cb", public: true, message: "wildcards"},
	{name: "fragment", uri: "https://app.example.com/cb#frag", message: "fragment"},
	{name: "empty fragment", uri: "https://app.example.com/cb#", message: "fragment"},
	{name: "userinfo", uri: "https://user@app.example.com/cb", message: "userinfo"},
	{name: "userinfo with a password", uri: "https://user:" + "hunter2@app.example.com/cb", message: "userinfo"},
	{name: "userinfo that looks like a host", uri: "https://good.example@evil.example/cb", message: "userinfo"},
	{name: "userinfo that looks like a port", uri: "https://good.example:443" + "@evil.example/cb", message: "userinfo"},
	{name: "at sign in the path", uri: "https://app.example.com/@evil", message: "userinfo"},
	{name: "empty", uri: "", message: "between 1 and 2048"},
	{name: "too long", uri: "https://app.example.com/" + strings.Repeat("a", 2030), message: "between 1 and 2048"},
	{name: "no host", uri: "https:///cb", message: "absolute URL with a host"},
	{name: "no host and a port", uri: "https://:443/cb", message: "absolute URL with a host"},
	{name: "opaque", uri: "https:app.example.com", message: "must start with https://"},
	{name: "empty port", uri: "https://app.example.com:/cb", message: "absolute URL with a host"},
	{name: "non-numeric port", uri: "https://app.example.com:http/cb", message: "absolute URL with a host"},
	{name: "port out of range", uri: "https://app.example.com:65536/cb", message: "port must be between 1 and 65535"},
	{name: "port zero", uri: "https://app.example.com:0/cb", message: "port must be between 1 and 65535"},
	{name: "port that overflows", uri: "https://app.example.com:99999999999999999999/cb", message: "port must be between 1 and 65535"},
	{name: "percent-encoded host", uri: "https://app.example.com%2eevil.example/cb", message: "absolute URL with a host"},
	{name: "host with an underscore", uri: "https://app_x.example.com/cb", message: "host name or an IP address"},
	{name: "host with a leading hyphen", uri: "https://-app.example.com/cb", message: "host name or an IP address"},
	{name: "IPv6 zone", uri: "https://[fe80::1%25eth0]/cb", message: "host name or an IP address"},
}

func TestRedirectURIProblem(t *testing.T) {
	for _, tc := range redirectCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			got := RedirectURIProblem(tc.uri, tc.public)
			if tc.message == "" {
				g.Expect(got).To(BeEmpty())
				return
			}
			g.Expect(got).To(ContainSubstring(tc.message))
		})
	}
}

func TestWebOriginProblem(t *testing.T) {
	for _, tc := range []struct {
		name    string
		origin  string
		public  bool
		message string
	}{
		{name: "https", origin: "https://app.example.com"},
		{name: "https with a port", origin: "https://app.example.com:8443"},
		{name: "http loopback, public", origin: "http://localhost:3000", public: true},
		{name: "http loopback, confidential", origin: "http://localhost:3000", message: "only on a public client"},
		{name: "wildcard", origin: "*", message: "wildcards"},
		{name: "plus", origin: "+", message: "must start with https://"},
		{name: "path", origin: "https://app.example.com/app", message: "must be an origin"},
		{name: "trailing slash", origin: "https://app.example.com/", message: "must be an origin"},
		{name: "query", origin: "https://app.example.com?x=1", message: "must be an origin"},
		{name: "http on another host", origin: "http://app.example.com", public: true, message: "localhost or 127.0.0.1 exactly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			got := WebOriginProblem(tc.origin, tc.public)
			if tc.message == "" {
				g.Expect(got).To(BeEmpty())
				return
			}
			g.Expect(got).To(ContainSubstring(tc.message))
		})
	}
}
