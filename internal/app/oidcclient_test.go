package app

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/craftainer-labs/lib-operator-go/pkg/apis/common"
	"github.com/craftainer-labs/lib-operator-go/pkg/conditions"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/controller"
)

// The OidcClient controller indexes its claims by provider once: a second
// registration on the same manager is refused, with the controller's own error.
func TestClientControllerRefusesASecondRegistration(t *testing.T) {
	g := NewWithT(t)
	mgr, err := ctrl.NewManager(testCfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	g.Expect(err).NotTo(HaveOccurred())
	r := &controller.ClientReconciler{Config: controller.Config{Client: mgr.GetClient()}}
	g.Expect(r.SetupWithManager(mgr)).To(Succeed())
	g.Expect(r.SetupWithManager(mgr)).NotTo(Succeed())
}

// A claim reaches the controller through the real API server: its provider has
// no admin Secret, so it says so in its conditions and Events, makes no binding
// Secret, and is released when deleted.
func TestOidcClientOnAProviderThatCannotBeUsed(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	c, err := client.New(testCfg, client.Options{Scheme: scheme})
	g.Expect(err).NotTo(HaveOccurred())
	err = c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "claims"}})
	g.Expect(client.IgnoreAlreadyExists(err)).To(Succeed())

	provider := &oidcv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "nokey", Namespace: "claims"}}
	provider.Spec.ProviderConfig = oidcv1alpha1.ProviderConfig{
		Type: oidcv1alpha1.ProviderKeycloak, Issuer: "https://127.0.0.1/realms/main",
		Keycloak: &oidcv1alpha1.KeycloakConfig{BaseURL: "https://127.0.0.1", Realm: "main"},
	}
	provider.Spec.AdminCredentialsSecretRef = &common.AdminSecretRef{Name: "missing"}
	g.Expect(c.Create(ctx, provider)).To(Succeed())
	claim := &oidcv1alpha1.OidcClient{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "claims"}}
	claim.Spec.ServerRef = common.ServerRef{Kind: "IdentityProvider", Name: "nokey"}
	claim.Spec.RedirectURIs = []oidcv1alpha1.RedirectURI{"https://app.example/cb"}
	g.Expect(c.Create(ctx, claim)).To(Succeed())
	t.Cleanup(func() { _ = c.Delete(ctx, provider) })

	stop := start(t, []string{"--health-probe-bind-address=" + freeAddr(t), "--metrics-bind-address=0", "--webhook-port=-1"})
	defer func() { _ = stop() }()

	synced := func() (string, error) {
		if err := c.Get(ctx, client.ObjectKeyFromObject(claim), claim); err != nil {
			return "", err
		}
		cond := meta.FindStatusCondition(claim.Status.Conditions, conditions.Synced)
		if cond == nil {
			return "", nil
		}
		return string(cond.Status), nil
	}
	g.Eventually(synced, 30*time.Second, 200*time.Millisecond).Should(Equal("False"))
	var s corev1.Secret
	g.Expect(client.IgnoreNotFound(c.Get(ctx, client.ObjectKey{Namespace: "claims", Name: "web"}, &s))).To(Succeed())
	g.Expect(s.Data).To(BeEmpty())

	// A claim that never made a client is released without its provider.
	g.Expect(c.Delete(ctx, claim)).To(Succeed())
	g.Eventually(func() bool {
		return apierrors.IsNotFound(c.Get(ctx, client.ObjectKeyFromObject(claim), &oidcv1alpha1.OidcClient{}))
	}, 30*time.Second, 200*time.Millisecond).Should(BeTrue())
	g.Expect(stop()).To(Succeed())
}
