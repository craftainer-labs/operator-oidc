package v1alpha1

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
)

var oidcclientlog = logf.Log.WithName("oidcclient-resource")

// SetupOidcClientWebhookWithManager registers the OidcClient webhooks with the manager.
func SetupOidcClientWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &oidcv1alpha1.OidcClient{}).
		WithValidator(&OidcClientValidator{Reader: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-oidc-craftainer-dev-v1alpha1-oidcclient,mutating=false,failurePolicy=fail,sideEffects=None,groups=oidc.craftainer.dev,resources=oidcclients,verbs=create;update,versions=v1alpha1,name=voidcclient-v1alpha1.kb.io,admissionReviewVersions=v1

// WebOriginsIgnoredWarning is the admission warning for an OidcClient that sets
// webOrigins on a provider that registers clients dynamically.
const WebOriginsIgnoredWarning = "spec.webOrigins is ignored: the provider registers clients by dynamic registration (RFC 7591), which has no web origins field"

// OidcClientValidator validates OidcClients on create and update.
type OidcClientValidator struct {
	// Reader reads the providers, to warn about settings a provider ignores. Nil
	// (or a provider it cannot read) means no warning: the provider may be
	// created later, and the controller reports what it ignores in a condition.
	Reader client.Reader
}

// ValidateCreate implements admission.Validator.
func (v *OidcClientValidator) ValidateCreate(ctx context.Context, obj *oidcv1alpha1.OidcClient) (admission.Warnings, error) {
	oidcclientlog.Info("validating create", "name", obj.GetName())
	return v.admit(ctx, obj)
}

// ValidateUpdate implements admission.Validator. An object that is being
// deleted is admitted while its spec is unchanged, so finalizer and metadata
// updates are never blocked; a spec change is still validated.
func (v *OidcClientValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *oidcv1alpha1.OidcClient) (admission.Warnings, error) {
	if !newObj.DeletionTimestamp.IsZero() && equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		return nil, nil
	}
	oidcclientlog.Info("validating update", "name", newObj.GetName())
	return v.admit(ctx, newObj)
}

// ValidateDelete implements admission.Validator; deletes are always admitted
// (the verbs marker above does not even send them here).
func (v *OidcClientValidator) ValidateDelete(_ context.Context, _ *oidcv1alpha1.OidcClient) (admission.Warnings, error) {
	return nil, nil
}

func (v *OidcClientValidator) validate(obj *oidcv1alpha1.OidcClient) error {
	return invalid("OidcClient", obj.GetName(), validateClient(&obj.Spec))
}

// admit validates the claim and, when it is valid, warns about what its
// provider ignores.
func (v *OidcClientValidator) admit(ctx context.Context, obj *oidcv1alpha1.OidcClient) (admission.Warnings, error) {
	if err := v.validate(obj); err != nil {
		return nil, err
	}
	if len(obj.Spec.WebOrigins) > 0 && v.providerType(ctx, obj) == oidcv1alpha1.ProviderDynamicRegistration {
		return admission.Warnings{WebOriginsIgnoredWarning}, nil
	}
	return nil, nil
}

// providerType is the type of the provider the claim names, or "" when there
// is no reader, the kind is unknown or the provider cannot be read.
func (v *OidcClientValidator) providerType(ctx context.Context, obj *oidcv1alpha1.OidcClient) oidcv1alpha1.ProviderType {
	if v.Reader == nil {
		return ""
	}
	ref := obj.Spec.ServerRef
	switch ref.Kind {
	case "ClusterIdentityProvider":
		var p oidcv1alpha1.ClusterIdentityProvider
		if v.Reader.Get(ctx, client.ObjectKey{Name: ref.Name}, &p) == nil {
			return p.Spec.Type
		}
	case "IdentityProvider":
		var p oidcv1alpha1.IdentityProvider
		if v.Reader.Get(ctx, client.ObjectKey{Namespace: obj.Namespace, Name: ref.Name}, &p) == nil {
			return p.Spec.Type
		}
	}
	return ""
}
