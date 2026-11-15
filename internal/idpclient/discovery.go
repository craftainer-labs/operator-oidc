package idpclient

import (
	"context"
	"net/http"
)

// maxEndpointLen is the longest endpoint the Discovery status fields hold (the
// CRD's maxLength).
const maxEndpointLen = 2048

// Discovery is what a provider's OpenID Provider Metadata document reported:
// the endpoints a client of the provider needs. An endpoint the document does
// not carry is empty.
type Discovery struct {
	TokenEndpoint         string
	AuthorizationEndpoint string
	JWKSURI               string
	UserinfoEndpoint      string
}

// discoveryDocument is the JSON of the document (OpenID Connect Discovery 1.0,
// section 3).
type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// Discover fetches the discovery document of issuer (its URL with
// /.well-known/openid-configuration appended, OpenID Connect Discovery 1.0,
// section 4) and returns the endpoints it names. The document is the provider's
// own word, so it is checked: its "issuer" must be exactly the issuer asked for
// (section 4.3, which stops a document being served for another issuer), and
// every endpoint it names must be an https URL without credentials, a query or
// a fragment that fits the status field. Anything else is ErrBadResponse; the
// answer's text is never part of an error.
func Discover(ctx context.Context, t Transport, issuer string) (Discovery, error) {
	base, err := parseHTTPS(issuer)
	if err != nil {
		return Discovery{}, err
	}
	c, err := newConn(t)
	if err != nil {
		return Discovery{}, err
	}
	defer c.CloseIdleConnections()
	const op = "fetch the discovery document"
	r, err := c.send(ctx, op, request{method: http.MethodGet, url: base.JoinPath(".well-known", "openid-configuration")})
	if err != nil {
		return Discovery{}, err
	}
	if r.status != http.StatusOK {
		return Discovery{}, r.failed(ctx, op)
	}
	var doc discoveryDocument
	if err := decode(r, &doc); err != nil {
		return Discovery{}, err
	}
	if doc.Issuer != issuer {
		return Discovery{}, ErrBadResponse
	}
	out := Discovery{
		TokenEndpoint: doc.TokenEndpoint, AuthorizationEndpoint: doc.AuthorizationEndpoint,
		JWKSURI: doc.JWKSURI, UserinfoEndpoint: doc.UserinfoEndpoint,
	}
	for _, e := range []string{out.TokenEndpoint, out.AuthorizationEndpoint, out.JWKSURI, out.UserinfoEndpoint} {
		if e == "" {
			continue
		}
		if _, err := parseHTTPS(e); err != nil || len(e) > maxEndpointLen {
			return Discovery{}, ErrBadResponse
		}
	}
	return out, nil
}
