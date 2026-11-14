package v1alpha1

import (
	"context"

	"k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
)

var oidcclientlog = logf.Log.WithName("oidcclient-resource")

// SetupOidcClientWebhookWithManager registers the OidcClient webhooks with the manager.
func SetupOidcClientWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &oidcv1alpha1.OidcClient{}).
		WithValidator(&OidcClientValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-oidc-craftainer-dev-v1alpha1-oidcclient,mutating=false,failurePolicy=fail,sideEffects=None,groups=oidc.craftainer.dev,resources=oidcclients,verbs=create;update,versions=v1alpha1,name=voidcclient-v1alpha1.kb.io,admissionReviewVersions=v1

// OidcClientValidator validates OidcClients on create and update.
type OidcClientValidator struct{}

// ValidateCreate implements admission.Validator.
func (v *OidcClientValidator) ValidateCreate(_ context.Context, obj *oidcv1alpha1.OidcClient) (admission.Warnings, error) {
	oidcclientlog.Info("validating create", "name", obj.GetName())
	return nil, v.validate(obj)
}

// ValidateUpdate implements admission.Validator. An object that is being
// deleted is admitted while its spec is unchanged, so finalizer and metadata
// updates are never blocked; a spec change is still validated.
func (v *OidcClientValidator) ValidateUpdate(_ context.Context, oldObj, newObj *oidcv1alpha1.OidcClient) (admission.Warnings, error) {
	if !newObj.DeletionTimestamp.IsZero() && equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		return nil, nil
	}
	oidcclientlog.Info("validating update", "name", newObj.GetName())
	return nil, v.validate(newObj)
}

// ValidateDelete implements admission.Validator; deletes are always admitted
// (the verbs marker above does not even send them here).
func (v *OidcClientValidator) ValidateDelete(_ context.Context, _ *oidcv1alpha1.OidcClient) (admission.Warnings, error) {
	return nil, nil
}

func (v *OidcClientValidator) validate(obj *oidcv1alpha1.OidcClient) error {
	return invalid("OidcClient", obj.GetName(), validateClient(&obj.Spec))
}
