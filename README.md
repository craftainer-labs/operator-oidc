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
holds the API (types, CRDs, admission webhooks); the controller follows.

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
`client_credentials` grant). Its `redirectUris`, `postLogoutRedirectUris` and
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
