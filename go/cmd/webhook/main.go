// Package main is the entrypoint for the VIBAP admission webhook.
// It validates and mutates agent pods based on their AgentPassport credentials.
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
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	vibapv1alpha1 "github.com/ArdurAI/ardur/go/pkg/api/v1alpha1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(vibapv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr     string
		healthProbeAddr string
		webhookPort     int
		certDir         string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Metrics endpoint bind address.")
	flag.StringVar(&healthProbeAddr, "health-probe-bind-address", ":8081", "Health probe bind address.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "Webhook server port.")
	flag.StringVar(&certDir, "cert-dir", "/tmp/k8s-webhook-server/serving-certs", "TLS certificate directory.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	logger := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(logger)
	setupLog := ctrl.Log.WithName("setup")

	webhookServer := webhook.NewServer(webhook.Options{
		Port:     webhookPort,
		CertDir:  certDir,
		CertName: "tls.crt",
		KeyName:  "tls.key",
	})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: healthProbeAddr,
		WebhookServer:          webhookServer,
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	decoder := admission.NewDecoder(scheme)
	validator := NewPodValidator(mgr.GetClient(), decoder)
	mutator := NewPodMutator(mgr.GetClient(), decoder)

	srv := mgr.GetWebhookServer()
	srv.Register("/validate-pods", &admission.Webhook{Handler: validator})
	srv.Register("/mutate-pods", &admission.Webhook{Handler: mutator})

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting VIBAP webhook server", "port", webhookPort, "certDir", certDir)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "webhook server exited with error")
		os.Exit(1)
	}
}
