# 0004. Manage cloud-hosted identity providers through the cloud API, starting with AWS Cognito

## Status

Proposed

## Context

Until now a provider was a server the operator reaches over HTTPS with an admin
credential it is given (Keycloak, or an RFC 7591 registration endpoint). AWS
Cognito has neither: its app clients are made with the Cognito user pools API,
under an AWS identity, and the pool, its domain and the IAM grants exist before
the operator does. lib-operator-go v0.6.0 adds the shared pieces for such
servers (`common.CloudServerCommon`, `server.ResolveCloud`, `CloudProber`,
`ServerStatus.Discovered`, `lifecycle.NonRotator`, `lifecycle.BindingRebuilder`;
its ADR 0002, section 16) and the egress-checked AWS client of `pkg/cloud`.

Cognito differs from the other two backends in ways that shape the design:

- An app client has no tag or attribute, so no ownership marker.
- A confidential client's secret is created with the client and cannot be
  rotated in place; overlapping rotation needs `AddUserPoolClientSecret`.
- `DescribeUserPoolClient` returns the client's secret at any time, so the
  binding Secret holds nothing the pool does not report again.
- `UpdateUserPoolClient` resets every field it is not given.

## Decision

- **A third provider type, `Cognito`, with a `cognito` block** (`region`,
  `userPoolID`, `domain`) on both provider kinds. The issuer is derived from the
  pool, so `issuer` and `adminCredentialsSecretRef` are forbidden, and the
  cloud credential is the library's `credentials` field (workload identity by
  default; a namespaced provider must name a Secret).
- **Failures show through the library's reasons.** The operator adds no
  condition type or reason of its own for a cloud provider: the probe's coarse
  error reaches `Ready` and `ServerReachable` and the log, in categories only
  (no ARN, account, credential or SDK text). The drafted server reasons of
  ADR 0002 section 16.1 (`TargetNotFound`, `EndpointOverrideForbidden`) are the
  library's to add; until then the provider cannot tell them apart on the
  resource, only in the message.
- **`status.discovered` holds only drafted keys**: `region`, `resourceId` (the
  pool ID) and `endpoint` (the hosted-UI host). The issuer is derived and lives
  in `status.discovery` and the binding; the account ID is not recorded.
- **Found by ID, never adopted.** The client is found by the app client ID in
  `status.externalId`. A client the status never recorded is not adopted, since
  nothing marks ownership. A create whose status write fails is deleted again.
- **The client is exactly its claim.** Create and update send the whole desired
  state; scopes, flows, URLs and identity providers are compared as sets, so a
  change behind the operator's back is drift. The secret cannot be gained or
  lost, so a changed `public` is a refused update (delete and recreate).
- **`NonRotator`.** `rotationPolicy` and the rotate annotation are acknowledged
  and ignored. Overlap rotation through `AddUserPoolClientSecret` is a later
  decision for the user; the SDK call is not exercised by the emulator.
- **`BindingRebuilder` re-fetches, never reissues.** A binding Secret that is
  gone is written again from `DescribeUserPoolClient`, which returns the
  existing secret. This stretches the interface beyond a backend that can only
  reissue, and is intended: reissuing would change a secret that workloads may
  still hold, for no gain. The library's documentation of the interface is
  clarified to match.
- **`cognito.domain` is held to a hostname pattern**, stricter than the drafted
  length limit alone, because the authorization, token and user info URLs are
  built from it.

## Consequences

- A tenant cannot end up with a client the operator cannot delete, and the
  operator never takes over a client it did not make; the cost is that a client
  that predates the claim must be recreated by the claim.
- A secret can only change by recreating the claim, which also changes the
  client ID.
- The failure reason on a Cognito provider is coarser than for a database server
  until the library drafts the cloud reasons.
- Every Cognito call goes through the egress policy; `endpointOverride` is
  honoured only with `EGRESS_MODE=allow-private`, for emulators.
- What the moto emulator cannot check is in NFR-0005.
