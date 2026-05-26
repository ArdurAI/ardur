// Package main is the entrypoint for the VIBAP operator.
// It runs the AgentPassport controller using controller-runtime.
package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	vibapv1alpha1 "github.com/ArdurAI/ardur/go/pkg/api/v1alpha1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(vibapv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		healthProbeAddr      string
		enableLeaderElection bool
		signingKeyPath       string
		issuerURI            string
		allowEphemeralKey    bool
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Metrics endpoint bind address.")
	flag.StringVar(&healthProbeAddr, "health-probe-bind-address", ":8081", "Health probe bind address.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for HA.")
	flag.StringVar(&signingKeyPath, "signing-key", "", "Path to Ed25519 signing key (JWK). Required in production.")
	flag.StringVar(&issuerURI, "issuer-uri", "https://vibap.ardur.dev", "Credential issuer URI.")
	// FIX-R9-6 (round-9, 2026-04-29): explicit opt-in for ephemeral
	// key generation. Without --signing-key AND without --allow-
	// ephemeral-key, the operator refuses to start.
	flag.BoolVar(&allowEphemeralKey, "allow-ephemeral-key", false,
		"Allow generating an ephemeral signing key when --signing-key is empty. "+
			"Use ONLY for local development; production deployments MUST supply "+
			"a persistent signing key.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)
	setupLog := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: healthProbeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "vibap-operator.ardur.dev",
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	reconciler, err := NewAgentPassportReconciler(mgr.GetClient(), mgr.GetScheme(), signingKeyPath, issuerURI, allowEphemeralKey)
	if err != nil {
		setupLog.Error(err, "unable to create reconciler")
		os.Exit(1)
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&vibapv1alpha1.AgentPassport{}).
		Complete(reconciler); err != nil {
		setupLog.Error(err, "unable to create controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting VIBAP operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager exited with error")
		os.Exit(1)
	}
}
