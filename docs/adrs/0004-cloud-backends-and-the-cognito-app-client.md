# 0004. Manage cloud-hosted identity providers through the cloud API: AWS Cognito and Microsoft Entra

## Status

Accepted

## Context

Until now a provider was a server the operator reaches over HTTPS with an admin
credential it is given (Keycloak, or an RFC 7591 registration endpoint). AWS
Cognito has neither: its app clients are made with the Cognito user pools API,
under an AWS identity, and the pool, its domain and the IAM grants exist before
the operator does. lib-operator-go v0.6.0 adds the shared pieces for such
servers (`common.CloudServerCommon`, `server.ResolveCloud`, `CloudProber`,
`ServerStatus.Discovered`, `lifecycle.NonRotator`, `lifecycle.BindingRebuilder`;
its ADR 0002, section 16) and the egress-checked AWS client of `pkg/cloud`.

Microsoft Entra is the second cloud backend, added in NKoidc-2. Its application
registrations are managed through Microsoft Graph, under an Entra identity, in a
tenant the administrator owns.

Cognito differs from the other two backends in ways that shape the design:

- An app client has no tag or attribute, so no ownership marker.
- A confidential client's secret is created with the client and cannot be
  rotated in place; overlapping rotation needs `AddUserPoolClientSecret`.
- `DescribeUserPoolClient` returns the client's secret at any time, so the
  binding Secret holds nothing the pool does not report again.
- `UpdateUserPoolClient` resets every field it is not given.

Entra differs from Cognito in the points below:

- An application registration has no tag the operator may rely on for ownership
  (the drafts of ADR 0002 section 16.6 say none), and its client secrets are
  readable only when issued.
- An application holds several client secrets, so a rotation can overlap.
- Graph is not an AWS-style service with a generated SDK worth linking: five
  stable v1.0 calls matter.

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

### Microsoft Entra

- **A fourth provider type, `Entra`, with an `entra` block** (`tenantID`, and
  `endpointOverride` on the cluster kind only; the lib's `AzureClusterBlock`) on
  both provider kinds. `subscriptionID` and `resourceGroup`, which the ARM-based
  operators need, are forbidden by CEL. The issuer is derived from the tenant, so
  `issuer` and `adminCredentialsSecretRef` are forbidden; `credentials` is the
  library's (Azure Workload Identity by default, or a Secret with `clientId` and
  `clientSecret`; a namespaced provider must name a Secret). The rules that the
  block matches `type` and that `type` cannot change also mean the block can be
  neither added to another type nor removed.
- **Graph REST over `net/http` and the egress policy, no `msgraph-sdk-go`.**
  Create, update and delete of an application, `addPassword` and
  `removePassword` do not justify about 24 modules and a generated model of all
  of Graph. Tokens come from azidentity through the library's `cloud.Egress.Azure`
  (workload identity or client secret), whose HTTP client dials through the
  policy; the Graph host is `graph.microsoft.com`, or the `endpointOverride` in
  tests. Every Graph answer is read for the few fields used, IDs are checked as
  GUIDs before they reach a path, and an error carries a status category, never
  the service's own words.
- **The probe needs no extra permission.** It gets a token and lists at most one
  application the identity owns; the permission is `Application.ReadWrite.OwnedBy`
  (admin consent), which the operator needs anyway. `/v1.0/organization` would
  need `Organization.Read.All`. `status.discovered` holds `resourceId` (the
  tenant ID) and `endpoint` (the authority host); there is no region, and no
  account ID.
- **Found by object ID, never adopted** (as for Cognito): no tag or note is
  written to the application, and an application the status never recorded is
  not taken over. Creating is idempotent instead: it is an upsert,
  `PATCH /v1.0/applications(uniqueName='<name>')` with `Prefer:
  create-if-missing` (Graph answers 201 for a new application and 204 for an
  existing one, which is then read), where the uniqueName is the claim's
  long-hash name (`naming.Tenant`). A retry after a lost answer or a failed
  status write therefore finds the application it made and never makes a
  second one, so nothing is deleted again after a failed status write. Observe
  keeps the read by object ID, and a 404 falls back to a read by uniqueName
  before the application is reported gone, since Graph is eventually
  consistent. This is not adoption: the operator holds only
  `Application.ReadWrite.OwnedBy`, so it can neither see nor change an
  application it does not own, and a uniqueName it finds is one of its own.
- **The application is exactly its claim.** Display name, audience
  (`AzureADMyOrg`), the redirect URIs of both platforms, the logout URL and the
  public flag are sent whole and compared. A changed `public` is a refused
  update. The claim's scopes must be OIDC scopes (`requiredResourceAccess`, API
  permissions and consent are not managed), and at most one post-logout redirect
  URI is allowed (the logout URL).
- **A real `Rotator`.** `RotateBegin` calls `addPassword` (named
  `craftainer-<sequence>`) first and returns the new key ID as the generation.
  Only then does it remove the secrets of the same name that a failed attempt
  left (the add succeeded and the binding was never written), except the one
  whose Graph `hint` (the first three characters of the secret) equals the first
  three characters of the secret the binding Secret holds: the binding stays
  valid until it is written again, no secret is removed before the new one
  exists, and the count stays bounded. `RotateFinish` calls `removePassword` for
  every secret but the active generation's and the binding's, which also retires
  the secret `Create` issued (the first rotation's previous generation, which
  the status never names) and a leaked one. A confidential application whose
  binding Secret is missing, empty or names a secret the application no longer
  has gets a new secret through the same path. A token fetch that times out or
  is answered with a 5xx is transient; a refusal of the credentials and a
  connection the egress policy refused are not. This is the existing claim
  semantics of a Keycloak client on a new backend, not a new behaviour.

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
- A cloud provider that is a Microsoft Entra tenant is tested against a fake
  Graph and a fake Entra token endpoint, since no emulator exists; what that
  cannot check is in NFR-0006.
- A secret on an Entra application can be rotated with an overlap, which a
  Cognito app client cannot (it is a `NonRotator`).
