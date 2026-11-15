// Package app builds and runs the operator's manager. cmd/main.go is a
// three-line wrapper around Run, so everything with a branch in it is here
// and under the coverage gate.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (OIDC, exec, ...) so the
	// manager can use any kubeconfig outside a cluster.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/craftainer-labs/lib-operator-go/pkg/binding"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/probe"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	oidcv1alpha1 "github.com/craftainer-labs/operator-oidc/api/v1alpha1"
	"github.com/craftainer-labs/operator-oidc/internal/controller"
	webhookv1alpha1 "github.com/craftainer-labs/operator-oidc/internal/webhook/v1alpha1"
	// +kubebuilder:scaffold:imports
)

// LeaderElectionID names the Lease the replicas elect a leader through. An
// instance renames it with the operator.
const LeaderElectionID = "operator-oidc.craftainer.dev"

// EventRecorderName is the reporting controller of the operator's Events.
const EventRecorderName = "operator-oidc"

var scheme = newScheme()

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(oidcv1alpha1.AddToScheme(s))
	// +kubebuilder:scaffold:scheme
	return s
}

// settings are the command-line flags.
type settings struct {
	metricsAddr      string
	secureMetrics    bool
	metricsCertPath  string
	metricsCertName  string
	metricsCertKey   string
	probeAddr        string
	probeOnly        bool
	leaderElect      bool
	leaderElectionNS string
	webhookPort      int
	webhookCertPath  string
	webhookCertName  string
	webhookCertKey   string
	enableHTTP2      bool
	egressMode       string
	operatorNS       string
	zap              zap.Options
}

func parseFlags(args []string, stderr io.Writer) (*settings, error) {
	s := &settings{}
	fs := flag.NewFlagSet("manager", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&s.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	fs.BoolVar(&s.secureMetrics, "metrics-secure", true,
		"Serve metrics over HTTPS with token authentication and authorization (TokenReview and SubjectAccessReview). "+
			"Use --metrics-secure=false for plain HTTP.")
	fs.StringVar(&s.metricsCertPath, "metrics-cert-path", "", "The directory that contains the metrics server certificate. "+
		"Empty: controller-runtime generates a self-signed one.")
	fs.StringVar(&s.metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	fs.StringVar(&s.metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	fs.StringVar(&s.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	fs.BoolVar(&s.probeOnly, "probe-only", os.Getenv("MANAGER_PROBE_ONLY") == "true",
		"Serve only /healthz and /readyz and never contact a cluster (the image smoke test). Default: $MANAGER_PROBE_ONLY.")
	fs.BoolVar(&s.leaderElect, "leader-elect", false, "Enable leader election, so only one replica reconciles.")
	fs.StringVar(&s.leaderElectionNS, "leader-election-namespace", "",
		"The namespace of the leader election Lease. Empty: the pod's namespace (needs the service account).")
	fs.IntVar(&s.webhookPort, "webhook-port", 9443, "Port the webhook server listens on. Set -1 to disable the webhooks.")
	fs.StringVar(&s.webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	fs.StringVar(&s.webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	fs.StringVar(&s.webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	fs.BoolVar(&s.enableHTTP2, "enable-http2", false, "Enable HTTP/2 on the metrics and webhook servers.")
	fs.StringVar(&s.egressMode, "egress-mode", os.Getenv(egress.EnvMode),
		"Which destinations the provider connections may not reach: strict (loopback, link-local, cloud metadata and private ranges) "+
			"or allow-private (all but the private ranges). Empty means strict. Default: $"+egress.EnvMode+".")
	fs.StringVar(&s.operatorNS, "operator-namespace", os.Getenv(server.OperatorNamespaceEnv),
		"The namespace cluster providers' admin Secrets and CA bundles are read from. Empty: the pod's namespace (needs the service account). Default: $"+
			server.OperatorNamespaceEnv+".")
	s.zap.BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return s, nil
}

// tlsOptions are applied to the metrics and webhook servers: TLS 1.2 or
// newer, and no HTTP/2 unless asked for (the Rapid Reset CVEs,
// GHSA-qppj-fm5r-hxr3 and GHSA-4374-p667-p6c8).
func (s *settings) tlsOptions() []func(*tls.Config) {
	opts := []func(*tls.Config){func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 }}
	if !s.enableHTTP2 {
		opts = append(opts, func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} })
	}
	return opts
}

func (s *settings) metricsOptions() metricsserver.Options {
	opts := metricsserver.Options{
		BindAddress:   s.metricsAddr,
		SecureServing: s.secureMetrics,
		TLSOpts:       s.tlsOptions(),
	}
	if s.secureMetrics {
		// Only callers RBAC lets `get` the /metrics non-resource URL are served.
		opts.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if s.metricsCertPath != "" {
		opts.CertDir = s.metricsCertPath
		opts.CertName = s.metricsCertName
		opts.KeyName = s.metricsCertKey
	}
	return opts
}

func (s *settings) webhookServer() webhook.Server {
	opts := webhook.Options{Port: s.webhookPort, TLSOpts: s.tlsOptions()}
	if s.webhookCertPath != "" {
		opts.CertDir = s.webhookCertPath
		opts.CertName = s.webhookCertName
		opts.KeyName = s.webhookCertKey
	}
	return webhook.NewServer(opts)
}

// serviceAccountNamespaceFile is where a pod finds its own namespace; tests
// point it elsewhere.
var serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// ErrNoOperatorNamespace means the operator cannot tell which namespace the
// admin Secrets of cluster providers are read from. Startup fails closed: a
// guessed namespace could be a tenant's.
var ErrNoOperatorNamespace = errors.New("cannot determine the operator namespace: set --operator-namespace or POD_NAMESPACE, or run in a pod with a service account")

// controllerSettings are the checked settings the controllers are built from.
type controllerSettings struct {
	egress    egress.Policy
	namespace string
}

// controllerSettings validates the egress mode and the operator namespace, so a
// wrong setting stops the operator at startup.
func (s *settings) controllerSettings() (controllerSettings, error) {
	mode, err := egress.ParseMode(s.egressMode)
	if err != nil {
		return controllerSettings{}, fmt.Errorf("%s: %w", egress.EnvMode, err)
	}
	ns := s.operatorNS
	if ns == "" {
		if b, err := os.ReadFile(serviceAccountNamespaceFile); err == nil {
			ns = strings.TrimSpace(string(b))
		}
	}
	if ns == "" {
		return controllerSettings{}, ErrNoOperatorNamespace
	}
	ctrl.Log.WithName("setup").Info("controller settings", "egressMode", string(mode), "operatorNamespace", ns)
	return controllerSettings{egress: egress.NewPolicy(mode), namespace: ns}, nil
}

// Option adjusts the manager's options; tests use it, the binary passes none.
type Option func(*ctrl.Options)

func (s *settings) managerOptions(opts []Option) ctrl.Options {
	o := ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 s.metricsOptions(),
		HealthProbeBindAddress:  s.probeAddr,
		LeaderElection:          s.leaderElect,
		LeaderElectionID:        LeaderElectionID,
		LeaderElectionNamespace: s.leaderElectionNS,
		// The process exits as soon as the manager stops, so giving up the
		// Lease on cancel is safe and makes a rollout faster.
		LeaderElectionReleaseOnCancel: true,
		// The Secret cache holds only the Secrets with the operator's managed-by
		// label, and the ConfigMap cache (the probes' watches) only the
		// ConfigMaps with the same label, so the operator does not keep or watch
		// every Secret and ConfigMap of the cluster. The admin Secrets and CA
		// bundles of providers are read from the API server on demand: the
		// client bypasses the cache for Secrets and ConfigMaps. An unlabelled
		// one that changes is seen at the next probe interval.
		Cache: cache.Options{ByObject: cacheByObject()},
		Client: client.Options{Cache: &client.CacheOptions{
			DisableFor: []client.Object{&corev1.Secret{}, &corev1.ConfigMap{}},
		}},
	}
	if s.webhookPort >= 0 {
		o.WebhookServer = s.webhookServer()
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// checker is the part of ctrl.Manager that registers probes.
type checker interface {
	AddHealthzCheck(name string, check healthz.Checker) error
	AddReadyzCheck(name string, check healthz.Checker) error
}

func addChecks(mgr checker) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add ready check: %w", err)
	}
	return nil
}

// Run starts the operator and blocks until ctx is cancelled or the manager
// fails. getConfig is only called when a cluster is needed.
func Run(ctx context.Context, args []string, getConfig func() (*rest.Config, error), stderr io.Writer, opts ...Option) error {
	s, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	// Structured JSON logs by default (EB-7); --zap-devel switches to console.
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&s.zap), zap.WriteTo(stderr)))

	if s.probeOnly {
		return serveProbes(ctx, s.probeAddr)
	}

	// Before a cluster is contacted: a wrong setting stops the operator here.
	cs, err := s.controllerSettings()
	if err != nil {
		return err
	}
	cfg, err := getConfig()
	if err != nil {
		return fmt.Errorf("load the Kubernetes client configuration: %w", err)
	}
	mgr, err := ctrl.NewManager(cfg, s.managerOptions(opts))
	if err != nil {
		return fmt.Errorf("create the manager: %w", err)
	}
	if err := setupManager(mgr, s.webhookPort >= 0, cs); err != nil {
		return err
	}
	ctrl.Log.WithName("setup").Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("run the manager: %w", err)
	}
	return nil
}

type setupStep struct {
	name string
	fn   func(ctrl.Manager) error
}

// The manager's access to the group's kinds, and to what the provider probes
// and the connection resolution read besides them. The ClusterRole lists exact
// resources and verbs. Secrets are the admin Secrets and initial access tokens
// of providers and CA bundles may be Secrets too; namespaced providers keep
// theirs in tenant namespaces, so the rule cannot be narrowed by namespace
// (NFR-0003). The probes (probe.Reconciler) watch Secrets and ConfigMaps, which
// is why both need list and watch; both caches are restricted to the managed-by
// label. Namespaces are read to check a cluster provider's allowedNamespaces.
//
// +kubebuilder:rbac:groups=oidc.craftainer.dev,resources=identityproviders;clusteridentityproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups=oidc.craftainer.dev,resources=oidcclients,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=oidc.craftainer.dev,resources=identityproviders/status;oidcclients/status;clusteridentityproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=oidc.craftainer.dev,resources=oidcclients/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core;events.k8s.io,resources=events,verbs=create;patch

// providerCacheIdle is how long a provider's client is kept without a use.
const providerCacheIdle = 10 * time.Minute

// setupManager is a variable so a test can make the set-up fail: no step can
// fail on a healthy manager.
var setupManager = setup

// setup registers the probes, the provider controllers and, when they are
// enabled, the webhooks.
func setup(mgr ctrl.Manager, webhooks bool, cs controllerSettings) error {
	steps := []setupStep{
		{"probes", func(mgr ctrl.Manager) error { return addChecks(mgr) }},
	}
	if webhooks {
		steps = append(steps,
			setupStep{"cluster identity provider webhook", webhookv1alpha1.SetupClusterIdentityProviderWebhookWithManager},
			setupStep{"identity provider webhook", webhookv1alpha1.SetupIdentityProviderWebhookWithManager},
			setupStep{"OIDC client webhook", webhookv1alpha1.SetupOidcClientWebhookWithManager},
		)
	}
	conns := controller.NewProviderCache(providerCacheIdle)
	cfg := controller.Config{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Recorder: mgr.GetEventRecorder(EventRecorderName),
		ManagedBy: EventRecorderName, OperatorNamespace: cs.namespace, Egress: cs.egress, Cache: conns,
	}
	steps = append(steps,
		setupStep{"provider connection sweeper", func(mgr ctrl.Manager) error { return mgr.Add(conns) }},
		setupStep{"OidcClient controller", (&controller.ClientReconciler{Config: cfg}).SetupWithManager},
		setupStep{"ClusterIdentityProvider probe", providerProbe(mgr, cfg,
			func() probe.Server { return &oidcv1alpha1.ClusterIdentityProvider{} })},
		setupStep{"IdentityProvider probe", providerProbe(mgr, cfg,
			func() probe.Server { return &oidcv1alpha1.IdentityProvider{} })},
	)
	// +kubebuilder:scaffold:builder
	return runSteps(mgr, steps)
}

// cacheByObject restricts the Secret and the ConfigMap cache to the objects
// that carry the operator's managed-by label.
func cacheByObject() map[client.Object]cache.ByObject {
	byObject := binding.CacheByObject(EventRecorderName)
	byObject[&corev1.ConfigMap{}] = cache.ByObject{
		Label: labels.SelectorFromSet(labels.Set{binding.LabelManagedBy: EventRecorderName}),
	}
	return byObject
}

// providerProbe returns the setup of the probe.Reconciler of one provider kind,
// which writes the kind's status (serverVersion, lastProbeTime, Ready,
// ServerReachable and discovery) from a request of its own. Its Client reads
// Secrets and ConfigMaps live (managerOptions), and its watches on them go
// through the manager's caches, which hold only the managed-by labelled ones.
func providerProbe(mgr ctrl.Manager, cfg controller.Config, kind func() probe.Server) func(ctrl.Manager) error {
	return (&probe.Reconciler{
		Client: mgr.GetClient(), New: kind, Prober: controller.Prober{Config: cfg},
		Options: probe.Options{OperatorNamespace: cfg.OperatorNamespace},
	}).SetupWithManager
}

func runSteps(mgr ctrl.Manager, steps []setupStep) error {
	for _, step := range steps {
		if err := step.fn(mgr); err != nil {
			return fmt.Errorf("set up the %s: %w", step.name, err)
		}
	}
	return nil
}

// serveProbes answers /healthz and /readyz without a cluster, until ctx is
// cancelled. It exists so `make release-check` can smoke-test the image
// (scripts/image-smoke.sh polls a URL), which a manager that needs an API
// server could not answer.
func serveProbes(ctx context.Context, addr string) error {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux := http.NewServeMux()
	mux.Handle("/healthz", ok)
	mux.Handle("/readyz", ok)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	// The shutdown goroutine waits on runCtx, which is cancelled on every way
	// out of this function, so it cannot outlive a failed ListenAndServe.
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-runCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.ListenAndServe()
	stop()
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
