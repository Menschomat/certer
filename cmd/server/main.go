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

	"certer/internal/app/api"
	"certer/internal/app/cert"
	"certer/internal/app/config"
	legolog "github.com/go-acme/lego/v5/log"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	legolog.SetDefault(logger)

	// Load config
	cfg, err := config.Load()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}
	logger.Info("Starting server", "env", cfg.Env, "port", cfg.Port)

	// Context for application lifecycle
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Initialize certificate issuer
	issuer := cert.NewIssuer(cfg.ACMEDirectoryURL, cfg.CertStorageDir, cfg.DNSProvider, cfg.ChallengePort, cfg.ACMEProvider, cfg.EABKid, cfg.EABHmac, cfg.DNSResolvers)

	// Initialize and start background certificate scheduler
	var scheduler *cert.Scheduler
	if cfg.ACMEEmail != "" {
		scheduler = cert.NewScheduler(issuer, cfg.ACMEEmail, cfg.AllCertificates(), cfg.CertStorageDir, cfg.RenewThresholdDays, cfg.CheckIntervalHours)
		go scheduler.Start(serverCtx)
	} else {
		logger.Warn("Certificate scheduler not started: ACME_EMAIL must be configured")
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

	// Configure HTTPS http.Server with production timeouts
	srvHTTPS := &http.Server{
		Addr:         ":" + cfg.HTTPSPort,
		Handler:      srvAPI.Routes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Generate fallback self-signed certificate
	logger.Info("Generating temporary self-signed certificate for HTTPS")
	fallbackCert, err := generateSelfSignedCert()
	if err != nil {
		logger.Error("Failed to generate temporary self-signed certificate", "error", err)
		os.Exit(1)
	}

	srvHTTPS.TLSConfig = makeTLSConfig(cfg.CertStorageDir, cfg.SSLCertID, fallbackCert)

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

		// Trigger graceful shutdown of both servers
		var shutdownErr error
		if err := srv.Shutdown(shutdownCtx); err != nil {
			shutdownErr = err
			logger.Error("HTTP Shutdown failed", "error", err)
		}
		if err := srvHTTPS.Shutdown(shutdownCtx); err != nil {
			shutdownErr = err
			logger.Error("HTTPS Shutdown failed", "error", err)
		}
		if shutdownErr != nil {
			os.Exit(1)
		}
		serverStopCtx()
	}()

	// Start HTTP server in the background
	go func() {
		logger.Info("HTTP Server is running", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP Server listening failed", "error", err)
			os.Exit(1)
		}
	}()

	// Start HTTPS server in the foreground
	logger.Info("HTTPS Server is running", "addr", srvHTTPS.Addr)
	err = srvHTTPS.ListenAndServeTLS("", "")
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTPS Server listening failed", "error", err)
		os.Exit(1)
	}

	// Wait for server context to be fully done
	<-serverCtx.Done()
	logger.Info("Server stopped cleanly")
}
