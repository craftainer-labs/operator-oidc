package v1alpha1

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
)

var clusteridentityproviderlog = logf.Log.WithName("clusteridentityprovider-resource")

// SetupClusterIdentityProviderWebhookWithManager registers the ClusterIdentityProvider webhooks with the manager.
func SetupClusterIdentityProviderWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &oidcv1alpha1.ClusterIdentityProvider{}).
		WithValidator(&ClusterIdentityProviderValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-oidc-craftainer-dev-v1alpha1-clusteridentityprovider,mutating=false,failurePolicy=fail,sideEffects=None,groups=oidc.craftainer.dev,resources=clusteridentityproviders,verbs=create;update,versions=v1alpha1,name=vclusteridentityprovider-v1alpha1.kb.io,admissionReviewVersions=v1

// ClusterIdentityProviderValidator validates ClusterIdentityProviders on create and update.
type ClusterIdentityProviderValidator struct{}

// ValidateCreate implements admission.Validator.
func (v *ClusterIdentityProviderValidator) ValidateCreate(_ context.Context, obj *oidcv1alpha1.ClusterIdentityProvider) (admission.Warnings, error) {
	clusteridentityproviderlog.Info("validating create", "name", obj.GetName())
	return nil, v.validate(obj)
}

// ValidateUpdate implements admission.Validator. An object that is being
// deleted is admitted while its spec is unchanged, so finalizer and metadata
// updates are never blocked; a spec change is still validated.
func (v *ClusterIdentityProviderValidator) ValidateUpdate(_ context.Context, oldObj, newObj *oidcv1alpha1.ClusterIdentityProvider) (admission.Warnings, error) {
	if !newObj.DeletionTimestamp.IsZero() && equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		return nil, nil
	}
	clusteridentityproviderlog.Info("validating update", "name", newObj.GetName())
	return nil, v.validate(newObj)
}

// ValidateDelete implements admission.Validator; deletes are always admitted
// (the verbs marker above does not even send them here).
func (v *ClusterIdentityProviderValidator) ValidateDelete(_ context.Context, _ *oidcv1alpha1.ClusterIdentityProvider) (admission.Warnings, error) {
	return nil, nil
}

func (v *ClusterIdentityProviderValidator) validate(obj *oidcv1alpha1.ClusterIdentityProvider) error {
	return invalid("ClusterIdentityProvider", obj.GetName(), validateProvider(&obj.Spec.ProviderConfig, obj.Spec.ProxyURL))
}
