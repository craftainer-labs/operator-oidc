# operator-oidc

> [!NOTE]
> This repository is vibe coded with [Claude](https://claude.com/product/claude-code).

A Kubernetes operator that registers OpenID Connect clients on
[Keycloak](https://www.keycloak.org/) and on any identity provider that
supports dynamic client registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)
and [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592)). A team claims a client
with an `OidcClient`; the operator creates it on the provider and writes its
client id and secret to a binding Secret. It is built on
[`lib-operator-go`](https://github.com/craftainer-labs/lib-operator-go) and
kubebuilder v4, from the `template-k8s-operator` template. This repository
holds the API (types, CRDs, admission webhooks) and the backend clients
(`internal/idpclient`: the Keycloak Admin REST client and the RFC 7591/7592
dynamic client registration client, over lib-operator-go's egress policy, tested
against a real Keycloak by the `Integration` workflow) and the provider
controllers (health probe and discovery, below) and the `OidcClient` controller
("Clients", below).

## Custom resources

All three are in the API group `oidc.craftainer.dev/v1alpha1`. Samples are in
[`config/samples/`](config/samples/).

| Kind | Scope | What it is |
| --- | --- | --- |
| `ClusterIdentityProvider` | cluster | An identity provider many namespaces may claim clients from. `allowedNamespaces` is required (it fails closed) and `adminCredentialsSecretRef.namespace` is required. |
| `IdentityProvider` | namespaced | An identity provider only claims in its own namespace may use. Its admin Secret is in the same namespace. |
| `OidcClient` | namespaced | An OpenID Connect client on a provider (`serverRef`), with redirect URIs, grant types, scopes and a client type. Its credentials are written to a binding Secret. |

Both provider kinds set a `type` (immutable) and the block that matches it:

- `Keycloak`: `keycloak.baseURL` and `keycloak.realm`. The admin Secret holds
  the keys `clientId` and `clientSecret` of a service account that may manage
  clients in the realm.
- `DynamicRegistration`: `dynamicRegistration.registrationEndpoint` and an
  optional `initialAccessTokenSecretRef`.

They also set `issuer`, `allowedScopes`, and optionally `tls` (CA bundle, server
name, minimum version), `proxyURL` and `healthCheckInterval`. Every URL must be
an https URL with a host, without userinfo, query or fragment, and a proxy URL
carries no credentials.

An `OidcClient` is confidential by default (it gets a secret, and may rotate it
with `rotationPolicy`) or `public: true` (no secret, PKCE required, no
`client_credentials` grant). Its `redirectUris` (needed when `grantTypes`
includes `authorization_code`, which an unset `grantTypes` defaults to; a
`client_credentials`-only client needs none), `postLogoutRedirectUris` and
`webOrigins` are exact values, validated when the object is admitted:

- `https` only. `http` is allowed for the hosts `localhost` and `127.0.0.1`
  (compared exactly, so `http://localhost.evil.example` is refused), and only on
  a public client, as [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)
  describes for native apps. `[::1]` is not allowed.
- No wildcard, no fragment and no userinfo (an `@` anywhere), no backslash,
  space or non-ASCII character. `javascript:`, `data:` and custom schemes are
  not `https` URLs, so they are refused.
- A web origin is a scheme, a host and an optional port, with no path.

The CRD's CEL rules check these, and the validating webhooks parse every URI
again (`RedirectURIProblem` and `WebOriginProblem` in `internal/webhook/v1alpha1`,
which the controller reuses). Admission errors never echo a URL.

## Provider health

Each `ClusterIdentityProvider` and `IdentityProvider` is probed every
`healthCheckInterval` (default 1 minute, plus up to 10% jitter) with
lib-operator-go's `probe.Reconciler`, which writes `status.conditions` (`Ready`
and `ServerReachable`), `status.lastProbeTime` and `status.observedGeneration`.
A provider is `Ready` when:

- its discovery document, fetched from `<issuer>/.well-known/openid-configuration`,
  names the issuer exactly as `spec.issuer` does (OpenID Connect Discovery 1.0,
  section 4.3), and every endpoint it names is an https URL without credentials,
  a query or a fragment; and
- for type `Keycloak`, the admin service account is accepted (one authenticated
  request for the realm's clients).

A provider of type `DynamicRegistration` is probed by its discovery document
alone: registering a client to try it would leave one behind, and the initial
access token can only be proved by using it. The document's `token_endpoint`,
`authorization_endpoint`, `jwks_uri` and `userinfo_endpoint` are copied to
`status.discovery` at the last successful probe; a failed probe leaves them as
they were. A changed document is written with the probe's next status write.

Every request goes through the egress policy (`EGRESS_MODE`, see below), the
provider's own `proxyURL` and its `tls` settings. A condition carries one fixed
text per kind of failure, and the log the same: never an address, a URL, a
token or the provider's own words (NFR-0002). Admin Secrets and CA
bundles are read live, not from a cache (a cluster provider's from the operator
namespace, a namespaced one's from its own); the operator's Secret and ConfigMap caches hold only objects labelled
`app.kubernetes.io/managed-by=operator-oidc`, so a change to an unlabelled
Secret or ConfigMap is seen at the next probe interval, not at once.

The operator keeps one client per provider between reconciles (a Keycloak admin
token and its connections), replaced when the provider, its credentials, its CA
bundle or its proxy change, and closed after 10 idle minutes.

## Clients

An `OidcClient` is reconciled with lib-operator-go's `lifecycle.Reconcile`
(finalizer, observe, create, update, drift poll, rotation) on both kinds of
provider. The client's credentials go to the binding Secret (`servicebinding.io/oidc`:
`issuer`, `clientId`, `clientSecret` for a confidential client, and the provider's
`tokenEndpoint`, `authorizationEndpoint`, `jwksUri` and `userinfoEndpoint` once
a probe found them); never to a status, an Event or a log.

- **Keycloak.** `status.externalName` is the client_id (derived once from the
  namespace and name) and `status.externalId` is Keycloak's own id. The client
  carries the claim's ownership marker as an attribute: a client of that name
  that carries it is adopted, one that does not is a `NameCollision`. `scopes`
  are exact: the client has these default client scopes and Keycloak's `basic`,
  and the realm's defaults (`roles`, `web-origins`, `profile`, `email`) are
  removed unless listed. The client is updated only when it differs from the
  spec. A rotation (`rotationPolicy`, or the `craftainer.dev/rotate` annotation)
  issues a new secret and, when the realm has a client policy with the
  secret-rotation executor, keeps the previous one valid for the grace period;
  without one it is a hard cut.
- **Dynamic registration.** The client is registered once (RFC 7591).
  `status.externalId` is the `client_id` the provider assigned, and
  `status.registrationClientUri` its management URI. The registration (client id,
  management URI and the registration access token) is a Secret named
  `dcr-<claim uid>` in the operator namespace, written again after every call,
  and the token is sent only to the registration endpoint's own origin. The
  client is read and updated with RFC 7592; a registration the provider no longer
  honours is `Synced=False` and is never registered again by the operator, since
  that would change the client_id its workload was given. A rotation registers a
  new client (the client_id changes) and deletes the old one, with no overlap.
  A claim whose `managementPolicies` lacks `Delete` keeps the Secret, labelled
  `craftainer.dev/orphaned=true`. A provider that answers a registration with a
  document the operator cannot use may have made a client it cannot manage: the
  claim gets the condition `RegistrationUnconfirmed` and a Warning Event. So
  does a client (on either kind of provider) that the status could not record
  and the operator could not delete again, with the reason `CleanupFailed`. The
  claim keeps such a client's id, so the next reconcile manages it; a client
  whose token is no longer held (the old registration of a rotation, or a
  registration whose state could not be stored) is only reported.
- **Web origins** are a Keycloak setting: RFC 7591 has no such field, so a
  dynamically registered client does not carry them. A claim that sets
  `webOrigins` on a `DynamicRegistration` provider is admitted, with an
  admission warning (`spec.webOrigins is ignored: ...`, shown by `kubectl`) and,
  while it is reconciled, the condition `WebOriginsIgnored=True` with a fixed
  message. The origins are dropped, not sent. The condition is removed when the
  claim no longer sets `webOrigins` or its provider is a Keycloak. The webhook
  reads the provider to warn; when it cannot (the provider does not exist yet),
  it admits without a warning, and the condition appears at the first reconcile
  that reaches the provider's client (a provider that cannot be resolved or
  built shows it once it can).
- **`openid` is strict.** A claim's `scopes` default to `openid`, and every scope
  of a claim, `openid` included, must be listed in the provider's
  `allowedScopes` (which defaults to `openid`, `profile` and `email`). A provider
  that sets `allowedScopes` without `openid` therefore refuses every claim that
  relies on the default scope, or that lists it: the claim gets `Synced=False`
  with the message `the scope "openid" is not in the provider's allowedScopes`,
  naming the first scope that is missing. List `openid` in the provider
  explicitly. On Keycloak `openid` is implicit and is no client scope, so listing
  it adds none.
- **Checked twice.** The controller checks the redirect URIs, post-logout redirect
  URIs, web origins and scopes (against `allowedScopes`) again, as the webhook
  does, and refuses a claim that broke them with a fixed text before it contacts
  the provider.

## Settings

| Setting | Flag | Environment | Default |
| --- | --- | --- | --- |
| Which destinations a provider connection may not reach: `strict` (loopback, link-local, cloud metadata and the private ranges) or `allow-private` (all but the private ranges) | `--egress-mode` | `EGRESS_MODE` | `strict` |
| The namespace cluster providers' admin Secrets and CA bundles are read from | `--operator-namespace` | `POD_NAMESPACE` | the pod's own namespace |

The chart sets both (`egressMode`, and the downward API for `POD_NAMESPACE`) and
rejects `manager.extraEnv` entries that use those names. A wrong value stops
the operator at startup. `allow-private` is for a provider or proxy on a
private address, the usual case inside a cluster; loopback, link-local and
cloud metadata addresses stay refused in both modes.

## Install

The operator needs a Kubernetes cluster at 1.33 or newer. Helm and OLM v1 need
[cert-manager](https://cert-manager.io/) for the webhooks' serving certificate;
OLM v0 issues its own, so it needs none. A release publishes the Helm chart, an
OLM bundle, a file-based catalog and the distroless `nonroot` image, signed and
attested (`release-extras.yml`, see "Releases" below and `docs/TEMPLATE.md`).
The registry and path come from the repository's `OCI_REGISTRY` variable and the
release workflow.

### Helm

```sh
helm install operator-oidc oci://<registry>/<path>/operator-oidc \
  --version X.Y.Z --namespace operator-oidc-system --create-namespace \
  --set egressMode=allow-private
```

A released chart pins the manager image by digest. Values worth knowing (the
schema, `charts/chart/values.schema.json`, rejects a misspelt enum or digest and
a name in `manager.extraEnv` that the chart sets itself):

| Value | Default | Meaning |
| --- | --- | --- |
| `egressMode` | `strict` | `allow-private` is the usual choice when a provider or its proxy is an in-cluster Service or lives on a private address |
| `global.imageRegistry` | empty | pull the image from a mirror (air-gapped) |
| `manager.image.digest` | set when released | image by digest; wins over `tag` |
| `manager.extraEnv` | `[]` | extra environment, rendered after the chart's own (not `POD_NAMESPACE` or `EGRESS_MODE`: the chart sets them, and the schema rejects them here), e.g. `NO_PROXY` or `HTTPS_PROXY` for the Kubernetes API client (the Go client reads them; the operator's own code does not), or `SSL_CERT_FILE` with a bundle mounted through `manager.extraVolumes` and `manager.extraVolumeMounts` |
| `manager.podSecurityContext`, `manager.securityContext` | restricted | non-root, seccomp `RuntimeDefault`, no privilege escalation, all capabilities dropped, read-only root filesystem; the e2e installs into a `restricted` namespace as an arbitrary UID |
| `crd.keep` | `true` | keep the CRDs, and with them every claim, when the release is uninstalled |

The operator makes no outbound call except to the Kubernetes API and to the
providers named by the provider kinds, and it sends no telemetry. A provider's
proxy and CA bundle belong to the provider object (`spec.proxyURL`,
`spec.tls.caBundle`), not to the chart.

The CSV therefore declares `features.operators.openshift.io/proxy-aware: "false"`:
the operator reads no `HTTP(S)_PROXY` (a provider connection takes its proxy from
`spec.proxyURL`), and the in-cluster Kubernetes API client needs no proxy.
`disconnected` is `"true"` and the fips, tls-profiles and token-auth features are
`"false"`.

### OLM

`make bundle` writes the bundle from `config/manifests` (`make bundle-validate`
checks it offline; `bundle/` is generated and not committed, and the CSV's
permissions come from `config/rbac/role.yaml`). It supports `AllNamespaces` only,
pins the manager image by digest and lists it in `spec.relatedImages`. Add the
released catalog as a `CatalogSource` (OLM v0) or a `ClusterCatalog` (OLM v1) and
subscribe or create a `ClusterExtension`.

From a checkout, `make deploy` installs the kustomize manifests of
`config/default`, which also need cert-manager.

## Backup and restore

The operator holds no data of its own: everything it knows is in Kubernetes
objects and at the identity provider.

| Kept in | What | Back it up with |
| --- | --- | --- |
| Kubernetes | the three kinds and their status (`status.externalName`, `status.externalId`, `status.registrationClientUri`, the rotation state), the binding Secrets (`servicebinding.io/oidc`), the providers' admin Secrets, initial access token Secrets and CA bundles, and, for dynamically registered clients, the registration Secrets `dcr-<claim uid>` in the operator namespace | your cluster backup (Velero, GitOps, etcd). Restore the providers and their Secrets first, then the claims |
| The identity provider | the clients, their secrets and (Keycloak) the realm's client policies | the provider's own backup (for Keycloak, a realm export and its database) |

The operator never copies or restores provider state, and it cannot read a
secret back from a dynamic registration. What it does on a restore:

- **The ownership proof.** A Keycloak client carries the attribute
  `craftainer.dev/claim` = `<namespace>/<name>/<claim uid>`. A claim adopts the
  client of its name only when the marker is its own; a client of that name with
  another marker (or none) gives `Synced=False`, reason `NameCollision`, and
  nothing is changed. A restore that gives the claims new UIDs (Velero does)
  therefore meets `NameCollision` on every client that still exists. Either
  delete the client in Keycloak (after checking nobody uses it) and let the claim
  create it again, which issues a new secret and rewrites the binding Secret, or
  set the attribute to the claim's new UID. A restore that keeps UIDs (etcd) is
  seamless.
- **A restore from manifests (GitOps) carries no status.** A claim with no
  `status.externalId` has made nothing as far as it knows, so on Keycloak it
  adopts a client carrying its marker or reports `NameCollision`, and on a
  dynamic registration provider it registers a new client (a new `client_id`),
  leaving the old registration at the provider; remove that one at the provider.
  A cluster backup keeps the status only if it includes the status subresource.
- **Dynamic registration state.** The registration Secret `dcr-<claim uid>`
  holds the client id, its management URI and the registration access token.
  A claim whose Secret is gone (or sits under another UID) reports
  `Synced=False` ("the provider no longer holds the client's registration") and is
  never registered again by the operator, since that would change the
  `client_id` its workload was given. Recover by restoring the Secret, or delete
  the claim (a lost registration does not hold its deletion up) and create it
  again; remove the old client at the provider if it still exists.
- **Restoring the provider from an older copy:** a client made after the copy is
  missing, and the claim is created again with a new secret. A secret rotated
  since the copy is lost while the binding Secret still holds it; rotate the claim
  (`craftainer.dev/rotate`) to issue a new one.
- **Binding Secrets** are rewritten by the operator, so a restore of them is not
  required. A missing Secret, or one that does not hold the client's secret, is
  replaced through a rotation, not by reading the secret again.
- **The rotation grace period:** after a rotation both the previous and the new
  secret work for `rotationPolicy.gracePeriod`, then the operator removes the
  previous one. On Keycloak this needs a client policy with the secret-rotation
  executor in the realm; without one a rotation is a hard cut, and a dynamically
  registered client has no overlap either (a new client replaces the old one).

`deletionPolicy` does not apply to `OidcClient`: it is a credential kind with no
`deletionPolicy`. Deleting a claim deletes its client at the provider (a claim
whose `managementPolicies` lacks `Delete` keeps it).

- A claim that never made a client (`status.externalId` is not set, for example
  a `NameCollision`) is released without contacting the provider.
- Otherwise the operator deletes the client it recorded; one that is already gone
  is a success.
- Delete the claims before the provider object: with the provider or its admin
  Secret gone, the claim cannot be cleaned up at the provider: its finalizer
  stays, and it reports `Synced=False` ("the referenced provider was not found")
  until the provider object and its Secret are back.
- Delete the claims before you uninstall the chart, and keep the provider and its
  admin Secret until the claims are gone: deleting a claim deletes its client, but
  only while the operator is running and the provider is reachable. Uninstalling
  the chart removes the operator; with the default `crd.keep=true` it keeps the
  CRDs, the claims and their clients, and a claim deleted afterwards stays
  `Terminating` until the operator is installed again. Removing its finalizer by
  hand releases the claim but leaves its client, with a valid secret, at the
  provider. Deleting a CRD, or uninstalling with `crd.keep=false`, deletes every
  claim of that kind: with the operator already gone they stay `Terminating` the
  same way and the CRD deletion waits for them.

## Development

Open the repository in its devcontainer (the Go and Kubernetes tools are
installed there), then:

```sh
make test          # unit + envtest, race detector, coverage gate
make test-e2e      # kind cluster + Chainsaw (needs ~2 GB free memory and Docker)
make helm-lint     # lint the chart, check it matches config/
make bundle-validate   # OLM bundle (operator-sdk) and catalog (opm)
make operator-help # every operator target
prek run --all-files --hook-stage manual   # all checks
```

## Releases

Releases go through `release.yml` as in `template-docker`; right after each
one, dispatch `release-extras.yml` to publish the chart, bundle and catalog
and to sign and attest them:

```sh
gh workflow run release-extras.yml -f tag=vX.Y.Z
```

It never publishes over an existing tag. If a run failed part-way (say the
chart and bundle were pushed and signing failed), finish it with
`-f resume=true`: artifacts whose tag exists are not pushed again, their
existing digests are signed (not again if they already verify) but never
attested, and missing ones are published and attested. SLSA provenance must
describe the run that built the artifact, so a resumed run does not claim it:
an existing artifact without provenance is named in a warning, and if
provenance is required for it, cut a new patch version instead.

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
