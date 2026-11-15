# NFR-0004. An OIDC client is exactly its spec, is checked again by the controller, and never leaks its credentials

## Status

Implemented

## Attribute

Security (access control, secrets, error handling; plan rows EB-3 and EB-9).

## Description

- **Scopes are exact.** A Keycloak client holds exactly the spec's scopes as
  default client scopes, plus Keycloak's `basic`. The realm's own defaults
  (`roles`, `web-origins`, `profile`, `email`) are removed unless listed, and a
  client that drifts is corrected. The controller passes the resolved defaults
  (scopes `openid`, grant `authorization_code`, PKCE `S256`) to `Client.Matches`
  and `Registration.Satisfies`, and calls an update only when they say the
  client differs. Every scope must be in the provider's `allowedScopes`.
- **Defence in depth.** The controller checks every redirect URI, post-logout
  redirect URI and web origin again with the webhook's `RedirectURIProblem` and
  `WebOriginProblem`, and the grant, PKCE and authentication method rules of the
  CRD, before anything is sent to a provider. A claim that reached the cluster
  without admission is refused with a fixed text. An empty `redirectUris` is
  valid for a `client_credentials`-only client.
- **Credentials only in Secrets.** The client secret goes to the binding Secret,
  and the registration state (client id, management URI and registration access
  token) to the `dcr-<claim uid>` Secret in the operator namespace. Neither is in
  a status, a condition, an Event or a log line. A public client's binding holds
  no secret.
- **The registration access token** is sent only to the registration endpoint's
  own origin (`idpclient` refuses any other stored management URI), and the state
  is stored again after every call that returns it.
- **No orphan is silent.** A provider that answers a registration with a document
  the operator cannot use may have made the client: the claim gets the condition
  `RegistrationUnconfirmed` and a Warning Event, and the log carries the failure
  category only. The same holds for a registration that cannot be stored and
  cannot be withdrawn, and for an old registration a rotation cannot delete.
- **Fixed texts.** A condition and an Event carry one fixed text per kind of
  failure (see NFR-0002), now including a name collision, an unknown scope, a
  lost registration and an invalid spec.

## Source

Plan Decision log: NR4, the user decision "scopes are exact" (2026-11-15), the NO6a-x decision
(`redirectUris` is optional unless `authorization_code` is granted), EB-3 and EB-9.
[ADR 0002 of lib-operator-go](https://github.com/craftainer-labs/lib-operator-go/blob/main/docs/adrs/0002-operator-crd-conventions.md), sections 7 to 10.

## Verification

`internal/controller`: `TestKeycloakClientLifecycle` (exact scopes and their
correction, no write while the client matches, the grace period),
`TestResolveSpec` and `TestKeycloakInvalidSpecIsRefusedAgain` (the controller's
second check, no request for an invalid spec), `TestDCRClientLifecycle` (the
state Secret, the token stored again, nothing in the status),
`TestDCRTokenGoesToTheProvidersOriginOnly`,
`TestDCRBadRegistrationAnswerIsAnOrphanRisk`, `TestDCRRegistrationThatCannotBeStored`
and `TestClientErrorTexts`. The Chainsaw test shows the failure conditions of a
claim without leaking the provider's address.
