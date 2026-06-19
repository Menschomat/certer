package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cert-central/internal/app/api"
	"cert-central/internal/app/cert"
	"cert-central/internal/app/config"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load config
	cfg := config.Load()
	logger.Info("Starting server", "env", cfg.Env, "port", cfg.Port)

	// Context for application lifecycle
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Initialize certificate issuer
	issuer := cert.NewIssuer(cfg.ACMEDirectoryURL, cfg.CertStorageDir, cfg.DNSProvider, cfg.ChallengePort, cfg.ACMEProvider, cfg.EABKid, cfg.EABHmac, cfg.DNSResolvers)

	// Initialize and start background certificate scheduler
	var scheduler *cert.Scheduler
	if cfg.ACMEEmail != "" && len(cfg.Certificates) > 0 {
		scheduler = cert.NewScheduler(issuer, cfg.ACMEEmail, cfg.Certificates, cfg.CertStorageDir, cfg.RenewThresholdDays, cfg.CheckIntervalHours)
		go scheduler.Start(serverCtx)
	} else {
		logger.Warn("Certificate scheduler not started: ACME_EMAIL and certificates list must be configured")
	}

	// Setup API server and routes
	srvAPI := api.NewServer(cfg.CertStorageDir, cfg, scheduler)

	// Configure http.Server with production timeouts
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      srvAPI.Routes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Listen for syscall signals for process shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		logger.Info("Shutdown signal received", "signal", sig.String())

		// Shutdown context with 30s timeout
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		go func() {
			<-shutdownCtx.Done()
			if errors.Is(shutdownCtx.Err(), context.DeadlineExceeded) {
				logger.Error("Graceful shutdown timed out. Forcing exit.")
				os.Exit(1)
			}
		}()

		// Trigger graceful shutdown
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("Shutdown failed", "error", err)
			os.Exit(1)
		}
		serverStopCtx()
	}()

	// Start server
	logger.Info("Server is running", "addr", srv.Addr)
	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Server listening failed", "error", err)
		os.Exit(1)
	}

	// Wait for server context to be fully done
	<-serverCtx.Done()
	logger.Info("Server stopped cleanly")
}
