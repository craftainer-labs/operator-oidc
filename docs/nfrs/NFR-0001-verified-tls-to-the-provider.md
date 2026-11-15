# NFR-0001. Every provider request is TLS 1.2 or newer and verifies the provider

## Status

Implemented (the clients and the provider controllers; the `OidcClient` controller follows in NO6b-2b)

## Attribute

Security (encryption in transit, FIPS-capable build, plan row EB-14).

## Description

- The operator reaches Keycloak and a dynamic-registration provider only over
  `https`. A provider URL (`keycloak.baseURL`, `dynamicRegistration.registrationEndpoint`)
  must be an https URL with a host and without `user:password@`, a query or a
  fragment (`idpclient.NewKeycloak`, `idpclient.NewDCR`; the CRDs and the webhooks
  check the same). There is no plaintext fallback.
- The provider's certificate chain and host name are verified against the
  provider's CA bundle (`tls.caBundle`; the system roots when there is none), with
  `tls.serverName` overriding the name. `InsecureSkipVerify` is never set. A
  bundle that holds no certificate is refused, not ignored. The TLS floor is 1.2
  (`tls.minVersion` may raise it to 1.3). HTTP/2 is not negotiated.
- A redirect is never followed: it would carry a bearer token to a host the egress
  policy has not seen named. The registration access token of a registered client
  is sent only to a management URI on the origin (scheme, host and port) of the
  registration endpoint: the provider chose that URI, and it is checked again
  every time it is read back from the Secret that stores it.
- A client takes the dialer it is given and builds its transport on it, with no
  environment proxy (see [NFR-0002](NFR-0002-restricted-egress-and-fixed-error-texts.md)).
- The build is FIPS-capable as `docs/TEMPLATE.md` and lib-operator-go's ADR 0002,
  section 13, describe; this package uses `crypto/tls` and `crypto/subtle` only.

## Source

Plan row EB-14; plan Decision log, NR4 (Keycloak Admin REST, RFC 7591 and RFC
7592);
[ADR 0002 of lib-operator-go](https://github.com/craftainer-labs/lib-operator-go/blob/main/docs/adrs/0002-operator-crd-conventions.md), sections 9 and 13.

## Verification

`TestNewKeycloak`, `TestNewDCR`, `TestNewConn` (`internal/idpclient`) cover the
URL, CA and dialer checks and that no error echoes the URL;
`TestTransportCategories` (an untrusted certificate, a wrong name, a TLS floor
above the server's, a plain server) and `TestTransportOptions` (name override,
TLS 1.3, keep-alive) cover the verification; `TestRedirectsAreNotFollowed` the
redirect; `TestDCRBadAnswers` and `TestDCRRefusals` that the registration access
token goes to the endpoint's own origin only. The integration lane
(`TestTLSIsVerifiedAndFailuresAreCategories`, `test/integration`) checks them
against a real Keycloak with TLS: an untrusted CA and a wrong name fail with the
fixed category, and TLS 1.3 works.
