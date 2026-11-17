# NFR-0005. The Cognito backend's tests say what they do not prove

## Status

Implemented (the `cognito` job of the `Integration` workflow)

## Attribute

Maintainability and security (test confidence).

## Description

The Cognito backend is exercised against [moto](https://github.com/getmoto/moto)
server 5.2.5, pinned by digest, in the `cognito` job of `integration.yml`, and
against a fake Cognito API in unit tests (100% coverage). The emulator proves the
shapes of the control-plane calls and the lifecycle of an app client; it cannot
check, and nothing in CI checks:

- **Credentials.** moto is not IRSA or EKS Pod Identity, does not enforce IAM,
  and accepts any signature. The workload identity path, `roleARN` assumption and
  the least-privilege permission list in the README are unverified until run
  against AWS.
- **Egress to AWS.** The test reaches moto at a private address with
  `EGRESS_MODE=allow-private`. The strict-mode path to the real endpoints, and
  the TLS to them, are covered by the library's own tests only.
- **The hosted UI and sign-in.** moto serves no hosted UI, OAuth endpoints or
  JWKS: the derived endpoints are checked as strings, not by a sign-in, and the
  `domain` is not checked to exist.
- **Overlap rotation.** moto does not implement `AddUserPoolClientSecret`, so
  that call (which the operator does not make) cannot be tested.
- **Real validation and limits.** Cognito's own refusals (a custom scope with no
  resource server, quotas, throttling, eventual consistency of a new client) are
  simulated by the fake in unit tests only; moto accepts more than AWS does.
- **Error text.** The operator shows only coarse categories (see
  [NFR-0002](NFR-0002-restricted-egress-and-fixed-error-texts.md)); what AWS
  actually says is never asserted.

## Source

The Cognito backend work (NKoidc-1) and [ADR 0004](../adrs/0004-cloud-backends-and-the-cognito-app-client.md).

## Verification

The `cognito` job runs on every push and pull request. The list above is
reviewed when the emulator's pin changes, and a manual run against a real pool
is needed before a release that changes this backend.
