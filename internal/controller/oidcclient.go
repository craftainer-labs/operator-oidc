package controller

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/dcr"
	"github.com/craftainer-labs/lib-operator-go/pkg/lifecycle"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/idpclient"
	webhookv1alpha1 "github.com/craftainer-labs/operator-oidc/internal/webhook/v1alpha1"
)

// ClientReconciler reconciles OidcClient claims (a credential kind) on both
// kinds of provider.
type ClientReconciler struct{ Config }

// Reconcile implements reconcile.Reconciler.
func (r *ClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var c oidcv1alpha1.OidcClient
	if err := r.Client.Get(ctx, req.NamespacedName, &c); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// A claim that is being deleted and never made a client has nothing at the
	// provider, which may be gone: it is released without contacting it.
	if !c.DeletionTimestamp.IsZero() && c.GetExternalID() == "" {
		return lifecycle.Reconcile[oidcv1alpha1.OidcClientSpec, clientState](ctx, r.Client, &c, c.Spec, nothingMade{}, r.options(nil))
	}
	be, err := r.Backend(ctx, c.Namespace, c.Spec.ServerRef)
	if be != nil {
		defer be.Release()
	}
	var ext lifecycle.External[oidcv1alpha1.OidcClientSpec, clientState]
	if err == nil {
		ext, err = r.external(ctx, be, &c)
	}
	opts := r.options(err)
	if be != nil {
		if u, perr := url.Parse(be.Conn.Endpoint); perr == nil {
			opts.ServerHost = u.Host
		}
	}
	return lifecycle.Reconcile(ctx, r.Client, &c, c.Spec, ext, opts)
}

// options are the lifecycle options of the controller; resolveErr is the error
// of resolving the provider, or nil.
func (r *ClientReconciler) options(resolveErr error) lifecycle.Options {
	return lifecycle.Options{
		Class: lifecycle.ClassCredential, BindingType: binding.TypeOIDC, Provider: binding.DefaultProvider,
		ManagedBy: r.ManagedBy, Recorder: r.Recorder, APIReader: r.APIReader, ResolveErr: resolveErr, Now: r.Now,
		// A client the operator stops managing keeps its registration state, so
		// an administrator can still manage it through RFC 7592.
		OnOrphan: func(ctx context.Context, claim lifecycle.Claim) error { return r.store().Orphan(ctx, claim) },
	}
}

func (r *ClientReconciler) store() dcr.Store {
	return dcr.Store{Client: r.Client, Namespace: r.OperatorNamespace, ManagedBy: r.ManagedBy}
}

// external builds the External of the claim on the resolved provider.
func (r *ClientReconciler) external(_ context.Context, be *Backend, c *oidcv1alpha1.OidcClient) (lifecycle.External[oidcv1alpha1.OidcClientSpec, clientState], error) {
	b := base{cfg: r.Config, claim: c, be: be}
	b.persist = func(ctx context.Context) error { return r.Client.Status().Update(ctx, c) }
	x := &clientExternal{claim: c}
	x.want, x.wantErr = resolveSpec(c.Spec, be.Spec.AllowedScopes)
	x.webOriginsDropped = be.Spec.Type != oidcv1alpha1.ProviderKeycloak && len(c.Spec.WebOrigins) > 0
	var cog *cognitoDriver
	var ent *entraDriver
	switch be.Spec.Type {
	case oidcv1alpha1.ProviderKeycloak:
		k, err := be.Keycloak()
		if err != nil {
			return nil, err
		}
		x.drv = &keycloakDriver{base: b, k: k}
		x.name = idpclient.KeycloakClientID(c.Namespace, c.Name)
	case oidcv1alpha1.ProviderCognito:
		api, err := be.Cognito()
		if err != nil {
			return nil, err
		}
		cog = &cognitoDriver{base: b, api: api, pool: be.UserPoolID}
		x.name = idpclient.CognitoClientName(c.Namespace, c.Name)
	case oidcv1alpha1.ProviderEntra:
		api, err := be.Entra()
		if err != nil {
			return nil, err
		}
		ent = &entraDriver{base: b, api: api}
		x.name = idpclient.EntraAppName(c.Namespace, c.Name)
	default:
		d, err := be.DCR()
		if err != nil {
			return nil, err
		}
		x.drv = &dcrDriver{base: b, d: d, store: r.store()}
		x.name = idpclient.DCRClientName(c.Namespace, c.Name)
	}
	// Observe goes by status.externalName, never by re-deriving (ADR 0002,
	// section 3); the name is derived once, at the first reconcile.
	if n := c.GetExternalName(); n != "" {
		x.name = n
	}
	c.SetExternalName(x.name)
	if cog != nil {
		// A Cognito app client cannot rotate its secret: it is no Rotator.
		return &cognitoExternal{claim: c, drv: cog, name: x.name, want: x.want, wantErr: x.wantErr, webOriginsDropped: x.webOriginsDropped}, nil
	}
	if ent != nil {
		// An application can hold several secrets, so it rotates with an overlap.
		wantErr := x.wantErr
		if wantErr == nil {
			wantErr = entraScopeProblem(x.want.scopes)
		}
		return &entraExternal{claim: c, drv: ent, name: x.name, want: x.want, wantErr: wantErr, webOriginsDropped: x.webOriginsDropped}, nil
	}
	return x, nil
}

// clientSpec is the spec with every default resolved: what is sent to the
// provider and what Matches and Satisfies compare it with.
type clientSpec struct {
	public       bool
	redirectURIs []string
	postLogout   []string
	webOrigins   []string
	grants       []string
	method       string
	pkce         string
	scopes       []string
}

// resolveSpec resolves the defaults of a spec and checks it again: the CRD's
// rules and the webhook have checked it at admission, but a claim may reach the
// cluster without either (the webhook disabled, a restored backup), and a
// redirect URI is where the provider sends codes and tokens. No error carries a
// value of the spec.
func resolveSpec(spec oidcv1alpha1.OidcClientSpec, allowed []oidcv1alpha1.Scope) (clientSpec, error) {
	w := clientSpec{public: spec.Public, method: string(spec.TokenEndpointAuthMethod), pkce: string(spec.PKCE)}
	for _, u := range spec.RedirectURIs {
		if webhookv1alpha1.RedirectURIProblem(string(u), spec.Public) != "" {
			return w, ErrInvalidClient
		}
		w.redirectURIs = append(w.redirectURIs, string(u))
	}
	for _, u := range spec.PostLogoutRedirectURIs {
		if webhookv1alpha1.RedirectURIProblem(string(u), spec.Public) != "" {
			return w, ErrInvalidClient
		}
		w.postLogout = append(w.postLogout, string(u))
	}
	for _, o := range spec.WebOrigins {
		if webhookv1alpha1.WebOriginProblem(string(o), spec.Public) != "" {
			return w, ErrInvalidClient
		}
		w.webOrigins = append(w.webOrigins, string(o))
	}
	for _, g := range spec.GrantTypes {
		w.grants = append(w.grants, string(g))
	}
	if len(w.grants) == 0 {
		w.grants = []string{string(oidcv1alpha1.GrantAuthorizationCode)}
	}
	for _, s := range spec.Scopes {
		w.scopes = append(w.scopes, string(s))
	}
	if len(w.scopes) == 0 {
		w.scopes = []string{"openid"}
	}
	if w.pkce == "" {
		w.pkce = string(oidcv1alpha1.PKCES256)
	}
	if w.method == "" {
		w.method = string(oidcv1alpha1.AuthMethodClientSecretBasic)
		if w.public {
			w.method = string(oidcv1alpha1.AuthMethodNone)
		}
	}
	// The authorization_code grant needs somewhere to send the user back to;
	// a client_credentials-only client has none.
	switch {
	case slices.Contains(w.grants, string(oidcv1alpha1.GrantAuthorizationCode)) && len(w.redirectURIs) == 0,
		w.public && slices.Contains(w.grants, string(oidcv1alpha1.GrantClientCredentials)),
		w.public && w.pkce == string(oidcv1alpha1.PKCEDisabled),
		(w.method == string(oidcv1alpha1.AuthMethodNone)) != w.public:
		return w, ErrInvalidClient
	}
	for _, s := range w.scopes {
		if !slices.Contains(allowed, oidcv1alpha1.Scope(s)) {
			return w, &scopeNotAllowedError{scope: s}
		}
	}
	return w, nil
}

// scopeNotAllowedError is ErrScopeNotAllowed with the scope that is missing from
// the provider's allowedScopes. A scope name is not sensitive (the CRD limits it
// to printable ASCII without a space or a quote), and naming it is what tells
// the author what to fix: `openid` is not allowed unless the provider lists it.
type scopeNotAllowedError struct{ scope string }

func (e *scopeNotAllowedError) Error() string {
	return fmt.Sprintf("the scope %q is not in the provider's allowedScopes", e.scope)
}

func (e *scopeNotAllowedError) Unwrap() error { return ErrScopeNotAllowed }

// clientState is what Observe read of the client at the provider: Keycloak's
// own representation, the stored registration of a dynamically registered
// client, the ID and secret of a Cognito app client, or an Entra application's IDs.
type clientState struct {
	kc  idpclient.Client
	reg dcr.State
	cog cognitoState
	ent entraState
}

// driver is the provider-specific half of the External.
type driver interface {
	observe(ctx context.Context, w clientSpec, wantErr error) (lifecycle.Observation[clientState], error)
	create(ctx context.Context, w clientSpec) (binding.Data, error)
	update(ctx context.Context, w clientSpec, cur clientState) (binding.Data, error)
	delete(ctx context.Context, cur clientState) error
	rotateBegin(ctx context.Context, w clientSpec, cur clientState) (binding.Data, error)
	rotateFinish(ctx context.Context) error
	// hardCut says whether the last rotateBegin left no overlap.
	hardCut() bool
}

// clientExternal is the lifecycle.Rotator of one OidcClient (ADR 0002, section
// 8). Every error it returns is coarse: a fixed text per kind of failure.
type clientExternal struct {
	claim   *oidcv1alpha1.OidcClient
	drv     driver
	name    string
	want    clientSpec
	wantErr error
	// webOriginsDropped says the claim sets webOrigins and its provider
	// registers clients dynamically, which has no field for them.
	webOriginsDropped bool
}

var (
	_ lifecycle.Rotator[oidcv1alpha1.OidcClientSpec, clientState] = (*clientExternal)(nil)
	_ lifecycle.HardCutRotator                                    = (*clientExternal)(nil)
)

// Observe implements lifecycle.External. A spec the controller refuses gives no
// wanted state, so the client is never up to date and Update reports it;
// deleting does not need a valid spec.
func (e *clientExternal) Observe(ctx context.Context, _ oidcv1alpha1.OidcClientSpec) (lifecycle.Observation[clientState], error) {
	// Reconcile adds the finalizer with a patch that replaces the claim with
	// the server's copy, which loses a name set before it; set it again here.
	e.claim.SetExternalName(e.name)
	e.noteWebOrigins()
	obs, err := e.drv.observe(ctx, e.want, e.wantErr)
	return obs, coarse(ctx, "observe", err)
}

// Create implements lifecycle.External.
func (e *clientExternal) Create(ctx context.Context, _ oidcv1alpha1.OidcClientSpec) (binding.Data, error) {
	if e.wantErr != nil {
		return nil, coarse(ctx, "create", e.wantErr)
	}
	data, err := e.drv.create(ctx, e.want)
	return data, coarse(ctx, "create", err)
}

// Update implements lifecycle.External.
func (e *clientExternal) Update(ctx context.Context, _ oidcv1alpha1.OidcClientSpec, cur clientState) (binding.Data, error) {
	if e.wantErr != nil {
		return nil, coarse(ctx, "update", e.wantErr)
	}
	data, err := e.drv.update(ctx, e.want, cur)
	return data, coarse(ctx, "update", err)
}

// Delete implements lifecycle.External: the client goes with the claim.
func (e *clientExternal) Delete(ctx context.Context, cur clientState) error {
	return coarse(ctx, "delete", e.drv.delete(ctx, cur))
}

// RotateBegin implements lifecycle.Rotator.
func (e *clientExternal) RotateBegin(ctx context.Context, _ oidcv1alpha1.OidcClientSpec, cur clientState, st lifecycle.RotationState) (binding.Data, lifecycle.Generation, error) {
	if e.wantErr != nil {
		return nil, "", coarse(ctx, "rotate", e.wantErr)
	}
	data, err := e.drv.rotateBegin(ctx, e.want, cur)
	if err != nil {
		return nil, "", coarse(ctx, "rotate", err)
	}
	return data, lifecycle.Generation(strconv.FormatInt(st.Sequence+1, 10)), nil
}

// RotateFinish implements lifecycle.Rotator.
func (e *clientExternal) RotateFinish(ctx context.Context, _ oidcv1alpha1.OidcClientSpec, _ clientState, _ lifecycle.RotationState) error {
	return coarse(ctx, "rotate", e.drv.rotateFinish(ctx))
}

// HardCut implements lifecycle.HardCutRotator.
func (e *clientExternal) HardCut() bool { return e.drv.hardCut() }

// nothingMade is the External of a claim that never made a client: nothing of
// it is at the provider, so there is nothing to observe or delete.
type nothingMade struct{}

// Observe implements lifecycle.External: nothing exists.
func (nothingMade) Observe(context.Context, oidcv1alpha1.OidcClientSpec) (lifecycle.Observation[clientState], error) {
	return lifecycle.Observation[clientState]{}, nil
}

// Create implements lifecycle.External; it is never called, because nothing exists.
func (nothingMade) Create(context.Context, oidcv1alpha1.OidcClientSpec) (binding.Data, error) {
	return nil, nil
}

// Update implements lifecycle.External; it is never called, because nothing exists.
func (nothingMade) Update(context.Context, oidcv1alpha1.OidcClientSpec, clientState) (binding.Data, error) {
	return nil, nil
}

// Delete implements lifecycle.External: there is nothing to delete.
func (nothingMade) Delete(context.Context, clientState) error { return nil }

// base is what both drivers share.
type base struct {
	cfg   Config
	claim *oidcv1alpha1.OidcClient
	be    *Backend
	// persist writes the claim's status now, instead of at the end of the
	// reconcile: a client the provider made is recorded before anything else
	// can fail.
	persist func(context.Context) error
}

// data is the oidc binding of the client (ADR 0002, section 7). The secret is
// empty for a public client. The endpoints are what the provider's last probe
// found.
func (b *base) data(clientID, secret string) binding.Data {
	d := binding.Data{"issuer": []byte(b.be.Issuer), "clientId": []byte(clientID)}
	if secret != "" {
		d["clientSecret"] = []byte(secret)
	}
	if disc := b.be.Discovery; disc != nil {
		for k, v := range map[string]string{
			"tokenEndpoint": disc.TokenEndpoint, "authorizationEndpoint": disc.AuthorizationEndpoint,
			"jwksUri": disc.JWKSURI, "userinfoEndpoint": disc.UserinfoEndpoint,
		} {
			if v != "" {
				d[k] = []byte(v)
			}
		}
	}
	return d
}

// currentSecret is the client secret the binding Secret holds, or "" when
// there is no Secret of this claim. It reads through the API reader, because
// the cache only holds Secrets with the operator's label. A Secret the claim
// does not control is not read: it is not the operator's.
func (b *base) currentSecret(ctx context.Context) (string, error) {
	var reader client.Reader = b.cfg.Client
	if b.cfg.APIReader != nil {
		reader = b.cfg.APIReader
	}
	var s corev1.Secret
	err := reader.Get(ctx, client.ObjectKey{Namespace: b.claim.Namespace, Name: b.claim.GetBindingSecretName()}, &s)
	if apierrors.IsNotFound(err) || (err == nil && !metav1.IsControlledBy(&s, b.claim)) {
		return "", nil
	}
	return string(s.Data["clientSecret"]), err
}

// The condition that says the claim's webOrigins are not used: a provider that
// registers clients dynamically has no field for them (RFC 7591). It is True
// while the claim sets webOrigins on such a provider and is removed otherwise.
const (
	conditionWebOriginsIgnored = "WebOriginsIgnored"
	reasonWebOriginsIgnored    = "WebOriginsIgnored"
	textWebOriginsIgnored      = "spec.webOrigins is ignored: the provider has no web origins field (dynamic registration, a Cognito app client and an Entra application have none)"
)

// noteWebOrigins sets the WebOriginsIgnored condition, or removes it when it no
// longer applies. The condition goes to the status with the reconcile's own
// write.
func (e *clientExternal) noteWebOrigins() { setWebOriginsCondition(e.claim, e.webOriginsDropped) }

// setWebOriginsCondition sets or removes the WebOriginsIgnored condition of a
// claim.
func setWebOriginsCondition(claim *oidcv1alpha1.OidcClient, dropped bool) {
	if !dropped {
		meta.RemoveStatusCondition(claim.GetConditions(), conditionWebOriginsIgnored)
		return
	}
	meta.SetStatusCondition(claim.GetConditions(), metav1.Condition{
		Type: conditionWebOriginsIgnored, Status: metav1.ConditionTrue, ObservedGeneration: claim.Generation,
		Reason: reasonWebOriginsIgnored, Message: textWebOriginsIgnored,
	})
}

// The condition that says a registration may exist at the provider that the
// operator holds no state for.
const (
	conditionRegistrationUnconfirmed = "RegistrationUnconfirmed"
	reasonRegistrationUnconfirmed    = "RegistrationUnconfirmed"
	textRegistrationUnconfirmed      = "a client may exist at the provider that the operator cannot manage: its registration was answered with an unexpected document, or it could not be taken back"
)

// reasonCleanupFailed is the reason of the condition when a client the status
// cannot account for could not be taken back. Unlike an unexpected answer, a
// later good registration does not clear it.
const reasonCleanupFailed = "CleanupFailed"

// orphanRisk records that a client may exist at the provider that the operator
// cannot manage: its registration was answered with a document the operator
// cannot use, or a client the status cannot account for could not be taken
// back. The condition goes to the status with the reconcile's own write;
// nothing but the fixed text is shown.
func (b *base) orphanRisk(reason string) {
	meta.SetStatusCondition(b.claim.GetConditions(), metav1.Condition{
		Type: conditionRegistrationUnconfirmed, Status: metav1.ConditionTrue, ObservedGeneration: b.claim.Generation,
		Reason: reason, Message: textRegistrationUnconfirmed,
	})
	b.cfg.Recorder.Eventf(b.claim, nil, corev1.EventTypeWarning, reason, "Register", "%s", textRegistrationUnconfirmed)
}

// clearOrphanRisk drops the condition once the client it was about is
// confirmed or adopted.
func (b *base) clearOrphanRisk() {
	meta.RemoveStatusCondition(b.claim.GetConditions(), conditionRegistrationUnconfirmed)
}

// clearUnexpectedAnswer drops the condition a good registration answers, and
// keeps one about a client that could not be taken back.
func (b *base) clearUnexpectedAnswer() {
	if c := meta.FindStatusCondition(*b.claim.GetConditions(), conditionRegistrationUnconfirmed); c != nil && c.Reason == reasonRegistrationUnconfirmed {
		b.clearOrphanRisk()
	}
}

// compensateTimeout bounds a compensating call. It runs on a context detached
// from the reconcile's: the reconcile may have been cancelled, and the client it
// made must still be taken back.
const compensateTimeout = 15 * time.Second

// detached is a short context for cleanup that has to outlive the reconcile's
// own, which keeps its values (logger) but not its cancellation.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), compensateTimeout)
}

// takeBack runs a compensating delete of a client or registration the status
// cannot account for, on a detached context. It reports whether the client is
// gone: a provider that no longer knows it counts as gone. Any other failure is
// an orphan risk (condition and Warning event), and the next reconcile retries.
func (b *base) takeBack(ctx context.Context, del func(context.Context) error) bool {
	ctx, cancel := detached(ctx)
	defer cancel()
	if err := del(ctx); err != nil && !clientGone(err) {
		b.orphanRisk(reasonCleanupFailed)
		return false
	}
	return true
}

// serverRefIndex indexes OidcClients by the provider they name, as kind/name.
const serverRefIndex = ".spec.serverRef"

func indexServerRef(o client.Object) []string {
	ref := o.(*oidcv1alpha1.OidcClient).Spec.ServerRef
	return []string{ref.Kind + "/" + ref.Name}
}

// clientsOfProvider maps a provider of a kind to the OidcClients that name it,
// so a client that waits for its provider is reconciled when the provider
// appears or changes. A namespaced provider serves its own namespace only.
func clientsOfProvider(c client.Reader, kind string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		opts := []client.ListOption{client.MatchingFields{serverRefIndex: kind + "/" + o.GetName()}}
		if o.GetNamespace() != "" {
			opts = append(opts, client.InNamespace(o.GetNamespace()))
		}
		var list oidcv1alpha1.OidcClientList
		if err := c.List(ctx, &list, opts...); err != nil {
			log.FromContext(ctx).Error(err, "cannot list the clients of a provider", "kind", kind, "provider", o.GetName())
			return nil
		}
		reqs := make([]reconcile.Request, len(list.Items))
		for i := range list.Items {
			reqs[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])}
		}
		return reqs
	}
}

// providerChanged lets a provider's creation and deletion through, and an
// update only when its spec changed: the status writes of a health probe would
// otherwise reconcile every client of the provider at every probe.
var providerChanged = predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
	return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
}}

// SetupWithManager registers the controller. It also watches the binding
// Secrets it owns (every change, so an edited Secret is repaired) and the
// providers its claims name (so a client that waits for its provider goes on
// when the provider exists). Only the claims themselves pass the lifecycle
// filter.
func (r *ClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &oidcv1alpha1.OidcClient{}, serverRefIndex, indexServerRef); err != nil {
		return err
	}
	reader := mgr.GetClient()
	return ctrl.NewControllerManagedBy(mgr).
		For(&oidcv1alpha1.OidcClient{}, builder.WithPredicates(lifecycle.Predicates())).
		Owns(&corev1.Secret{}).
		Watches(&oidcv1alpha1.ClusterIdentityProvider{},
			handler.EnqueueRequestsFromMapFunc(clientsOfProvider(reader, kindClusterIdentityProvider)),
			builder.WithPredicates(providerChanged)).
		Watches(&oidcv1alpha1.IdentityProvider{},
			handler.EnqueueRequestsFromMapFunc(clientsOfProvider(reader, kindIdentityProvider)),
			builder.WithPredicates(providerChanged)).
		WithOptions(ctrlcontroller.Options{MaxConcurrentReconciles: max(1, r.MaxConcurrentReconciles)}).
		Named("oidcclient").
		Complete(r)
}

// errLost is what a claim whose registration state is gone gets.
func errLost() error { return fmt.Errorf("%w: no stored registration", idpclient.ErrRegistrationLost) }

// clientGone reports a client or registration the provider does not know: a
// client that is not found, or a registration whose token it no longer honours.
func clientGone(err error) bool {
	return errors.Is(err, idpclient.ErrNotFound) || errors.Is(err, idpclient.ErrRegistrationLost)
}
