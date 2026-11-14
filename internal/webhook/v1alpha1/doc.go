// Package v1alpha1 holds the validating admission webhooks of the
// oidc.craftainer.dev API. Defaults and nearly every rule live in the CRD
// schema (OpenAPI and CEL); the webhooks check what CEL cannot do well: that
// the provider URLs and the redirect URIs and web origins of a client parse as
// URLs with a valid host and port, and that a proxy URL carries no
// credentials (credentials come only from Secret references). The redirect URI
// rules are exported (RedirectURIProblem, WebOriginProblem) so the controller
// can apply the same check before it registers a client. Admission errors never
// echo a URL, because a misplaced value can hold a password or a token.
// Updates of an object that is being deleted are always admitted, so finalizer
// removal is never blocked, for example while the webhook's own pod is down.
package v1alpha1
