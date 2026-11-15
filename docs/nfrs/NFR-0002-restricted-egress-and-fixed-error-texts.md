# NFR-0002. A tenant cannot aim the operator at internal addresses, and an error says nothing of the provider

## Status

Implemented (the clients; the controller that builds them follows in NO6b-2)

## Attribute

Security (server-side request forgery, multi-tenancy, plan rows EB-3 and EB-5).

## Description

A namespaced `IdentityProvider` lets a tenant name any host. Decided by the user
on 2026-11-03 and implemented once, in lib-operator-go's `pkg/egress`
([ADR 0002](https://github.com/craftainer-labs/lib-operator-go/blob/main/docs/adrs/0002-operator-crd-conventions.md), section 15):

- Every connection is checked after the host name has been resolved, when the
  socket is about to connect, against the deny list of `EGRESS_MODE` (`strict` by
  default, `allow-private` for clusters whose providers are on private
  addresses), and the provider's proxy (no credentials in its URL; `http`,
  `https` or `socks5`) is checked the same way. The clients take the
  `egress.DialFunc` of `Policy.HostDialer`, so no connection can bypass it, and
  they read no proxy variable. A client without a dialer is refused
  (`ErrNoDialer`). This repository carries no copy of the egress package.
- A failed request reaches conditions and Events as one fixed text per category
  (refused by the egress policy, TLS handshake failed, authentication failed,
  timed out, connection failed), as `lifecycle.ErrUnreachable` with the category,
  and a non-2xx answer as its status alone. Never an address, a URL, a token, a
  secret, the provider's own words or the raw error, so a tenant gets no port
  scan or name resolution out of the operator and a hostile provider cannot
  write into a condition. The logs carry the same categories and the HTTP status
  and nothing else.
- Identifiers that go into a URL path come from the provider (a Keycloak client
  or scope id) or from status, and are checked against the shape of a provider
  id before they are used (`ErrInvalidID`); a realm is checked against the CRD's
  pattern and refuses `.` and `..`.

## Source

Plan Decision log, 2026-11-03 (ADR 0002 open items), 2026-11-13 (NO2b review)
and 2026-11-14 (NOX-egress); plan rows EB-3 and EB-5.

## Verification

`TestTransportCategories` (`internal/idpclient`) shows that each way a request
can fail before an answer, among them a loopback address refused by the real
policy, is one category and that the error text holds nothing else;
`TestKeycloakBadAnswers`, `TestKeycloakTokenFailures`, `TestDCRRefusals` and
`TestDCRRegisterRefusals` that a status, a body or a wrong credential is not
echoed; `TestKeycloakEveryRequestMatters` that a failure of any request of an
operation reaches the caller without the body; `TestKeycloakRefusals` and
`TestNewKeycloak` the id and realm checks. The pkg/egress ranges, the proxies and
the deadlines are tested in lib-operator-go. The integration lane checks the
policy's refusal and the texts against a real Keycloak.
