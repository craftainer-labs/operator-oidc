# NFR-0006. The Entra backend's tests say what they do not prove

## Status

Implemented (the `entra` job of the `Integration` workflow)

## Attribute

Maintainability and security (test confidence).

## Description

There is no Microsoft Graph or Entra emulator. The Entra backend is exercised by
a fake Graph and a fake Entra token endpoint that the tests serve themselves
(`test/integration/entra`, in the `entra` job of `integration.yml`), through the
real controller, azidentity's client secret credential and the egress policy, and
by a fake Graph client in unit tests (100% coverage of the new code). The fakes
prove the shapes of the calls, the token request and the lifecycle of an
application (create, drift, rotation with overlap, delete); they cannot check,
and nothing in CI checks:

- **What real Graph and Entra do.** The fakes answer what the operator expects.
  Real Graph's validation, its limits (applications, secrets per application),
  its replication delay after a create, throttling and the 400 it answers for an
  unknown key ID are simulated by the fakes or unverified.
- **Admin consent and permissions.** The fakes enforce no permission model. That
  `Application.ReadWrite.OwnedBy` is enough, that the operator becomes the owner
  of what it creates, and that the probe's list call needs nothing more, are
  unverified until run against a tenant.
- **Conditional access.** A tenant's policies on the operator's identity are not
  modelled.
- **Workload Identity federation.** The tests use a client secret credential. The
  federated token exchange, the service account annotations and the pod label are
  covered by the library's own tests only.
- **Egress to Microsoft.** The test reaches the fakes at a private address over
  TLS with `EGRESS_MODE=allow-private` and a test-only trust root. The
  strict-mode path to `login.microsoftonline.com` and `graph.microsoft.com` is
  covered by the library's tests only.
- **Sign-in.** The derived issuer and endpoints are checked as strings, not by a
  sign-in or a token validation.
- **Error text.** The operator shows only coarse categories (see
  [NFR-0002](NFR-0002-restricted-egress-and-fixed-error-texts.md)); what Graph
  actually says is never asserted.

## Source

The Entra backend work (NKoidc-2) and [ADR 0004](../adrs/0004-cloud-backends-and-the-cognito-app-client.md).

## Verification

The `entra` job runs on every push and pull request. The list above is reviewed
when the Graph calls change, and a manual run against a real tenant is needed
before a release that changes this backend.
