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
controllers (health probe and discovery, below); the `OidcClient` controller
follows.

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

The operator needs a Kubernetes cluster at 1.33 or newer and
[cert-manager](https://cert-manager.io/) for its webhook certificates. A release
publishes three artifacts to the OCI registry (see "Releases" below):

- a Helm chart, `helm install operator-oidc oci://<registry>/<path>/operator-oidc --version X.Y.Z -n operator-oidc-system --create-namespace`;
- an OLM bundle and a file-based catalog, installable with OLM v0 and OLM v1's
  `ClusterExtension`;
- the distroless `nonroot` image the chart and bundle run.

The registry and path come from the repository's `OCI_REGISTRY` variable and
the release workflow. From a checkout, `make deploy` installs the kustomize
manifests of `config/default`.

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
