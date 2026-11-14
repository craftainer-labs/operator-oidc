package v1alpha1

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
)

var identityproviderlog = logf.Log.WithName("identityprovider-resource")

// SetupIdentityProviderWebhookWithManager registers the IdentityProvider webhooks with the manager.
func SetupIdentityProviderWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &oidcv1alpha1.IdentityProvider{}).
		WithValidator(&IdentityProviderValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-oidc-craftainer-dev-v1alpha1-identityprovider,mutating=false,failurePolicy=fail,sideEffects=None,groups=oidc.craftainer.dev,resources=identityproviders,verbs=create;update,versions=v1alpha1,name=videntityprovider-v1alpha1.kb.io,admissionReviewVersions=v1

// IdentityProviderValidator validates IdentityProviders on create and update.
type IdentityProviderValidator struct{}

// ValidateCreate implements admission.Validator.
func (v *IdentityProviderValidator) ValidateCreate(_ context.Context, obj *oidcv1alpha1.IdentityProvider) (admission.Warnings, error) {
	identityproviderlog.Info("validating create", "name", obj.GetName())
	return nil, v.validate(obj)
}

// ValidateUpdate implements admission.Validator. An object that is being
// deleted is admitted while its spec is unchanged, so finalizer and metadata
// updates are never blocked; a spec change is still validated.
func (v *IdentityProviderValidator) ValidateUpdate(_ context.Context, oldObj, newObj *oidcv1alpha1.IdentityProvider) (admission.Warnings, error) {
	if !newObj.DeletionTimestamp.IsZero() && equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		return nil, nil
	}
	identityproviderlog.Info("validating update", "name", newObj.GetName())
	return nil, v.validate(newObj)
}

// ValidateDelete implements admission.Validator; deletes are always admitted
// (the verbs marker above does not even send them here).
func (v *IdentityProviderValidator) ValidateDelete(_ context.Context, _ *oidcv1alpha1.IdentityProvider) (admission.Warnings, error) {
	return nil, nil
}

func (v *IdentityProviderValidator) validate(obj *oidcv1alpha1.IdentityProvider) error {
	return invalid("IdentityProvider", obj.GetName(), validateProvider(&obj.Spec.ProviderConfig, obj.Spec.ProxyURL))
}
