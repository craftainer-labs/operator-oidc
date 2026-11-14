package v1alpha1

import (
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
)

// redacted stands in for a URL in an error: a value can carry credentials
// (https://user:password@host, a token in a query), and an admission error is
// shown to the user and written to logs.
const redacted = "<redacted>"

// maxURLLength is the longest URL the API accepts (RedirectURI's maxLength).
const maxURLLength = 2048

// invalid turns a list of field errors into the 422 the API server returns,
// or nil for an empty list.
func invalid(kind, name string, errs field.ErrorList) error {
	if len(errs) == 0 {
		return nil
	}
	return apierrors.NewInvalid(schema.GroupKind{Group: oidcv1alpha1.GroupVersion.Group, Kind: kind}, name, errs)
}

// validateProvider checks the URLs and the proxy URL of a provider, for both
// provider kinds. No value appears in an error.
func validateProvider(spec *oidcv1alpha1.ProviderConfig, proxyURL string) field.ErrorList {
	var errs field.ErrorList
	path := field.NewPath("spec")
	check := func(p *field.Path, raw string) {
		if msg := httpsURLProblem(raw); msg != "" {
			errs = append(errs, field.Invalid(p, redacted, msg))
		}
	}
	check(path.Child("issuer"), string(spec.Issuer))
	if spec.Keycloak != nil {
		check(path.Child("keycloak", "baseURL"), string(spec.Keycloak.BaseURL))
	}
	if spec.DynamicRegistration != nil {
		check(path.Child("dynamicRegistration", "registrationEndpoint"), string(spec.DynamicRegistration.RegistrationEndpoint))
	}
	if proxyURL != "" {
		if msg := proxyProblem(proxyURL); msg != "" {
			errs = append(errs, field.Invalid(path.Child("proxyURL"), redacted, msg))
		}
	}
	return errs
}

// validateClient checks every redirect URI, post-logout redirect URI and web
// origin of an OidcClient. The CRD's CEL rules are a looser version of the same
// rules; this parses the URL and checks the host and the port, which CEL cannot
// do, and keeps the rules in force if the CRD is ever changed or replaced.
func validateClient(spec *oidcv1alpha1.OidcClientSpec) field.ErrorList {
	var errs field.ErrorList
	path := field.NewPath("spec")
	if len(spec.RedirectURIs) == 0 {
		errs = append(errs, field.Required(path.Child("redirectUris"), "at least one redirect URI is required"))
	}
	for i, uri := range spec.RedirectURIs {
		if msg := RedirectURIProblem(string(uri), spec.Public); msg != "" {
			errs = append(errs, field.Invalid(path.Child("redirectUris").Index(i), redacted, msg))
		}
	}
	for i, uri := range spec.PostLogoutRedirectURIs {
		if msg := RedirectURIProblem(string(uri), spec.Public); msg != "" {
			errs = append(errs, field.Invalid(path.Child("postLogoutRedirectUris").Index(i), redacted, msg))
		}
	}
	for i, origin := range spec.WebOrigins {
		if msg := WebOriginProblem(string(origin), spec.Public); msg != "" {
			errs = append(errs, field.Invalid(path.Child("webOrigins").Index(i), redacted, msg))
		}
	}
	return errs
}

// httpsURLProblem says what is wrong with an https URL of a provider (issuer,
// Keycloak base URL, registration endpoint), or returns "" for a good one: an
// absolute https URL with a valid host, without userinfo, query and fragment.
func httpsURLProblem(raw string) string {
	if msg := plainURLProblem(raw); msg != "" {
		return msg
	}
	if strings.ContainsAny(raw, "?#") {
		return "must not have a query or a fragment"
	}
	if !strings.HasPrefix(raw, "https://") {
		return "must be an https URL with a host"
	}
	if _, msg := parseHostURL(raw); msg != "" {
		return msg
	}
	return ""
}

// plainURLProblem checks what every URL of the API shares: a length, printable
// ASCII (no space, control character, non-ASCII character or backslash, which
// parsers and browsers read differently), no wildcard and no userinfo.
func plainURLProblem(raw string) string {
	if raw == "" || len(raw) > maxURLLength {
		return "must be between 1 and 2048 characters"
	}
	for i := range len(raw) {
		if c := raw[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			return "must contain only printable ASCII characters, without spaces or backslashes"
		}
	}
	if strings.Contains(raw, "*") {
		return "wildcards are not allowed"
	}
	if strings.Contains(raw, "@") {
		return "must not carry credentials or userinfo (user@host)"
	}
	return ""
}

// parseHostURL parses an absolute http or https URL with a host and checks the
// host and the port.
func parseHostURL(raw string) (*url.URL, string) {
	const notAbsolute = "must be an absolute URL with a host"
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") {
		return nil, notAbsolute
	}
	if !validHost(u.Hostname()) {
		return nil, "must have a host name or an IP address as its host"
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, "port must be between 1 and 65535"
		}
	}
	return u, ""
}

// validHost reports whether host is an IP address or a DNS-1123 subdomain
// (case-insensitive, as host names are; one trailing dot, the fully qualified
// form, is accepted).
//
// A name whose last label is all digits or starts with "0x" is refused: it is
// not a host name (RFC 3696, section 2) but, to a browser or a resolver, a
// shorthand IP address (https://2130706433, https://127.1, https://0x7f.1) that
// would slip past every loopback and internal-address rule.
func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	last := name[strings.LastIndex(name, ".")+1:]
	if last != "" && (strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "") {
		return false
	}
	return len(validation.IsDNS1123Subdomain(name)) == 0
}

// proxyProblem says what is wrong with a proxy URL, or returns "" for a good
// one: an http, https or socks5 URL with a host and without userinfo.
func proxyProblem(raw string) string {
	if strings.Contains(raw, "@") {
		return "must not carry credentials (user:password@); proxy credentials are not supported"
	}
	if msg := plainURLProblem(raw); msg != "" {
		return msg
	}
	if strings.ContainsAny(raw, "?#") {
		return "must not have a query or a fragment"
	}
	u, err := url.Parse(raw)
	if err != nil || !slices.Contains([]string{"http", "https", "socks5"}, u.Scheme) || u.Hostname() == "" ||
		u.Opaque != "" || strings.HasSuffix(u.Host, ":") {
		return "must be an http, https or socks5 URL with a host"
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "port must be between 1 and 65535"
		}
	}
	return ""
}
