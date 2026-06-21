package cert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"certer/internal/app/config"
)

// Scheduler coordinates periodic checks and renewals for SSL certificates.
type Scheduler struct {
	mu                 sync.RWMutex
	issuer             CertificateIssuer
	email              string
	certificates       []config.CertConfig
	storageDir         string
	renewThresholdDays int
	checkIntervalHours int
}

// NewScheduler instantiates a new Scheduler.
func NewScheduler(issuer CertificateIssuer, email string, certificates []config.CertConfig, storageDir string, renewThresholdDays, checkIntervalHours int) *Scheduler {
	return &Scheduler{
		issuer:             issuer,
		email:              email,
		certificates:       certificates,
		storageDir:         storageDir,
		renewThresholdDays: renewThresholdDays,
		checkIntervalHours: checkIntervalHours,
	}
}

// Start runs the periodic check-and-renew loop.
func (s *Scheduler) Start(ctx context.Context) {
	slog.Info("Starting certificate renewal scheduler", "interval_hours", s.checkIntervalHours)

	// Run initial check on startup
	if err := s.CheckAndRenew(ctx); err != nil {
		slog.Error("Initial check and renew failed", "error", err)
	}

	ticker := time.NewTicker(time.Duration(s.checkIntervalHours) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping certificate renewal scheduler")
			return
		case <-ticker.C:
			if err := s.CheckAndRenew(ctx); err != nil {
				slog.Error("Scheduled check and renew failed", "error", err)
			}
		}
	}
}

// CheckAndRenew checks current cert status for all configured certificate groups and triggers ACME renewal if necessary.
func (s *Scheduler) CheckAndRenew(ctx context.Context) error {
	s.mu.RLock()
	certs := make([]config.CertConfig, len(s.certificates))
	copy(certs, s.certificates)
	s.mu.RUnlock()

	for _, cc := range certs {
		if cc.ID == "" {
			continue
		}

		domains := append([]string{cc.Primary}, cc.Sans...)
		reason, err := s.needsRenewal(cc, domains)
		if err != nil {
			slog.Error("Failed to check certificate status", "id", cc.ID, "primary_domain", cc.Primary, "error", err)
			continue
		}

		if reason != "" {
			slog.Info("Certificate renewal triggered", "id", cc.ID, "primary_domain", cc.Primary, "reason", reason, "domains", domains)
			result, err := s.issuer.Issue(ctx, s.email, domains, cc.ID)
			if err != nil {
				slog.Error("Failed to issue certificate", "id", cc.ID, "primary_domain", cc.Primary, "error", err)
				continue
			}
			slog.Info("Certificate issued and saved successfully", "id", cc.ID, "domain", result.Domain)
			continue
		}

		slog.Info("Certificate is valid and configuration matches. No action required.", "id", cc.ID, "domain", cc.Primary)
	}

	s.cleanupUnusedCertificates()
	return nil
}

// cleanupUnusedCertificates deletes certificate and key files from the storage directory
// if they belong to a configuration ID that is no longer configured.
func (s *Scheduler) cleanupUnusedCertificates() {
	if s.storageDir == "" {
		return
	}
	files, err := os.ReadDir(s.storageDir)
	if err != nil {
		slog.Error("Failed to read storage directory for cleanup", "dir", s.storageDir, "error", err)
		return
	}

	// Create a map of configured IDs
	configured := make(map[string]bool)
	s.mu.RLock()
	for _, cc := range s.certificates {
		if cc.ID != "" {
			configured[cc.ID] = true
		}
	}
	s.mu.RUnlock()

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		var configID string
		var isCertOrKey bool
		ext := filepath.Ext(name)
		if ext == ".crt" || ext == ".key" {
			configID = strings.TrimSuffix(name, ext)
			isCertOrKey = true
		}

		if isCertOrKey && configID != "" {
			if !configured[configID] {
				path := filepath.Join(s.storageDir, name)
				slog.Info("Cleaning up unused certificate/key file", "file", name, "id", configID)
				if err := os.Remove(path); err != nil {
					slog.Error("Failed to remove unused certificate/key file", "file", name, "error", err)
				}
			}
		}
	}
}

// needsRenewal checks if a certificate needs to be renewed and returns the reason.
func (s *Scheduler) needsRenewal(cc config.CertConfig, domains []string) (string, error) {
	certPath := filepath.Join(s.storageDir, cc.ID+".crt")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "certificate file missing or unreadable", nil
	}

	keyPath := filepath.Join(s.storageDir, cc.ID+".key")
	if _, err := os.Stat(keyPath); err != nil {
		return "private key file missing or unreadable", nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return "failed to decode certificate PEM", nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "failed to parse certificate bytes", nil
	}

	// 1. Check expiration
	threshold := time.Duration(s.renewThresholdDays) * 24 * time.Hour
	timeToExpiry := time.Until(cert.NotAfter)
	if timeToExpiry < threshold {
		return fmt.Sprintf("certificate is expiring soon (expires in %v, threshold %v)", timeToExpiry, threshold), nil
	}

	// 2. Check configuration changes (compare cert DNSNames vs configured domains)
	if !domainsMatch(cert.DNSNames, domains) {
		return fmt.Sprintf("domains configuration changed (cert: %v, config: %v)", cert.DNSNames, domains), nil
	}

	return "", nil
}

func domainsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := make([]string, len(a))
	copy(ac, a)
	sort.Strings(ac)

	bc := make([]string, len(b))
	copy(bc, b)
	sort.Strings(bc)

	return reflect.DeepEqual(ac, bc)
}

// ReloadConfig updates the scheduler's certificates list in a thread-safe manner
// and immediately triggers a background check and renew cycle.
func (s *Scheduler) ReloadConfig(ctx context.Context, certificates []config.CertConfig) {
	s.mu.Lock()
	s.certificates = certificates
	s.mu.Unlock()

	slog.Info("Scheduler configuration reloaded, triggering immediate check and renew cycle")
	go func() {
		if err := s.CheckAndRenew(context.Background()); err != nil {
			slog.Error("Failed to execute check and renew cycle after reload", "error", err)
		}
	}()
}
