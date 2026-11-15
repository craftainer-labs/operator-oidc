# test/integration/

Go tests of the operator's backend clients (`internal/idpclient`) against a
real Keycloak 26.7.4 with TLS on and the preview feature
`client-secret-rotation`, behind the build tag `integration` so `go test ./...`
and the 100% coverage gate of `make test` never see them. The unit suites use
in-process fakes that speak just enough of the Admin REST API and of RFC 7591
and 7592; Keycloak's behaviour is server-side, so this lane checks what those
fakes only claim:

- the Admin REST calls (create, read by the stored id, update, delete, the
  secret and its rotation, the client scopes) and the shape of what Keycloak
  returns, which is what the controller compares with the claim's spec to tell
  a client is up to date;
- the settings a claim implies do what they say: PKCE on and off (an
  authorization request without a code challenge is refused), the post-logout
  redirect URIs apart from the redirect URIs (an empty list allows none), the
  `client_credentials` grant only where granted, and a client with no redirect
  URIs;
- the two-phase rotation with the realm's client policy: the previous secret
  works during the grace period and not after `FinishRotation`, and a retried
  `Rotate` adopts the first attempt instead of rotating again;
- the ownership marker: a client of the same `client_id` that is not ours is
  `ErrNameCollision`, and one that is ours is adopted;
- RFC 7591 registration and RFC 7592 read, update and delete against Keycloak's
  OpenID Connect registration endpoint with an initial access token;
- verified TLS: an untrusted CA and a wrong host name fail with the fixed
  category, the egress policy refuses the loopback address, and no error text
  holds the address or a secret.

Files:

- `keycloak_test.go` — the setup (a realm `operator-it` with a client policy
  that rotates the secret of every confidential client, and the operator's
  service account `operator` with the realm-management roles `manage-clients`
  and `view-clients` only) and the tests. They read `KEYCLOAK_ADDRESS` (default
  `https://localhost:8443`), `KEYCLOAK_CA_FILE` (required),
  `KEYCLOAK_ADMIN_USERNAME` (default `admin`) and `KEYCLOAK_ADMIN_PASSWORD_FILE`
  (required; the bootstrap administrator of the master realm, used for the setup
  and for what a test checks behind the operator's back). A missing setting fails
  the run; it never skips. Every test uses client ids of its own and removes what
  it created.
- `gen-certs.sh <dir>` — a throwaway CA, a server certificate for `localhost`,
  `keycloak` and `127.0.0.1` (`server.crt`, `server.key`, `ca.crt`) and the
  administrator's random password (`admin-password`), with `openssl`. The key is
  world-readable because Keycloak runs as another user than the one that
  generated it; the files live two days in a directory made for one run.

## Running

In CI, `.github/workflows/integration.yml` generates the files, starts the pinned
`quay.io/keycloak/keycloak:26.7.4` image (by digest) with TLS and the feature on
and runs the tests.

The devcontainer does not run a Keycloak for this repository, and the machines
that build it allow at most one Keycloak at a time, so this lane runs in CI only.
Anywhere else, run `gen-certs.sh` into a directory, start a server the way the
workflow does and export the `KEYCLOAK_*` variables:

```sh
go test -tags integration -count=1 ./test/integration/...
```

The integration coverage of the client (informational, the gate stays on the
unit profile):

```sh
go test -tags integration -count=1 -coverpkg=./internal/idpclient/ -coverprofile=integration.cover ./test/integration/...
go tool cover -func=integration.cover
```

The tests dial directly, not through the egress policy, which refuses loopback;
the policy is covered by its own tests in lib-operator-go and by one case here
that expects its refusal.

## Don't

- Point the tests at a server that holds anything you want to keep. They create
  a realm and remove only the clients they made, but they connect as the
  administrator.
