# NFR-0003. A credential lives only in its Secret, and a name cannot reach another tenant's client

## Status

Implemented (the clients and the provider controllers; the `OidcClient` controller follows in NO6b-2b)

## Attribute

Security (secrets, multi-tenancy, plan rows EB-3 and EB-9).

## Description

- The service account of a Keycloak provider, a dynamic-registration initial
  access token and the registration access token (RAT) of every registered client
  are credentials: they come from Secrets and go back only to Secrets
  (`dcr-<claim uid>` in the operator namespace, written by lib-operator-go's
  `dcr.Store`). The clients never put one in an error, a log line or a status;
  `dcr.State` prints its RAT as `<redacted>`. The RAT is re-stored after every
  update, because the provider may issue a new one.
- A client is found by the id the provider assigned (Keycloak's own id, the
  registered `client_id`), never by name. A Keycloak client carries the ownership
  marker `craftainer.dev/claim=<namespace>/<name>/<uid>` as an attribute; `Create`,
  `Get` and `Update` refuse a client whose marker is another's
  (`ErrNameCollision`), so a name clash cannot make the operator adopt or change
  another tenant's client. The names come from `naming.Tenant`
  (`KeycloakClientID` with the short hash, `DCRClientName` with the long one) and
  the claim cannot choose them.
- A rotation never leaves a consumer without a working secret: `Rotate` adopts a
  previous attempt's result instead of rotating again (Keycloak keeps one rotated
  secret, and a second rotation would push the one consumers hold out of it), and
  `FinishRotation` is the only call that invalidates the previous secret.
- The client keeps what it does not own: an update sends the representation it
  read back with its own fields replaced, so mappers and the attributes an
  administrator set are not dropped.

## Source

Plan rows EB-3 and EB-9; plan Decision log, NR4 (3, 4, 5);
[ADR 0002 of lib-operator-go](https://github.com/craftainer-labs/lib-operator-go/blob/main/docs/adrs/0002-operator-crd-conventions.md), sections 8, 9 and 10.

## Verification

`TestNames` (`internal/idpclient`) asserts the hash length each name passes;
`TestKeycloakRefusals` and `TestKeycloakLifecycle` the marker checks and that an
update keeps what it does not own; `TestKeycloakRotation` the adopted retry and
the finish; `TestDCRLifecycle` that the RAT of an update is returned for storing
and that the old one stops working. The integration lane checks the same against a
real Keycloak (`TestOwnershipAndDeletion`, `TestSecretRotation`,
`TestDynamicRegistration`).
