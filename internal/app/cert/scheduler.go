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
	"time"

	"cert-central/internal/app/config"
)

// Scheduler coordinates periodic checks and renewals for SSL certificates.
type Scheduler struct {
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
	for _, cc := range s.certificates {
		if cc.Primary == "" {
			continue
		}

		domains := append([]string{cc.Primary}, cc.Sans...)
		reason, err := s.needsRenewal(cc, domains)
		if err != nil {
			slog.Error("Failed to check certificate status", "primary_domain", cc.Primary, "error", err)
			continue
		}

		if reason != "" {
			slog.Info("Certificate renewal triggered", "primary_domain", cc.Primary, "reason", reason, "domains", domains)
			result, err := s.issuer.Issue(ctx, s.email, domains)
			if err != nil {
				slog.Error("Failed to issue certificate", "primary_domain", cc.Primary, "error", err)
				continue
			}
			slog.Info("Certificate issued and saved successfully", "domain", result.Domain)
		} else {
			slog.Info("Certificate is valid and configuration matches. No action required.", "domain", cc.Primary)
		}
	}

	s.cleanupUnusedCertificates()
	return nil
}

// cleanupUnusedCertificates deletes certificate and key files from the storage directory
// if they belong to a primary domain that is no longer configured.
func (s *Scheduler) cleanupUnusedCertificates() {
	if s.storageDir == "" {
		return
	}
	files, err := os.ReadDir(s.storageDir)
	if err != nil {
		slog.Error("Failed to read storage directory for cleanup", "dir", s.storageDir, "error", err)
		return
	}

	// Create a map of configured primary domains
	configured := make(map[string]bool)
	for _, cc := range s.certificates {
		if cc.Primary != "" {
			configured[cc.Primary] = true
		}
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		var domain string
		var isCertOrKey bool
		if strings.HasSuffix(name, ".crt") {
			domain = strings.TrimSuffix(name, ".crt")
			isCertOrKey = true
		} else if strings.HasSuffix(name, ".key") {
			domain = strings.TrimSuffix(name, ".key")
			isCertOrKey = true
		}

		if isCertOrKey && domain != "" {
			if !configured[domain] {
				path := filepath.Join(s.storageDir, name)
				slog.Info("Cleaning up unused certificate/key file", "file", name, "domain", domain)
				if err := os.Remove(path); err != nil {
					slog.Error("Failed to remove unused certificate/key file", "file", name, "error", err)
				}
			}
		}
	}
}

// needsRenewal checks if a certificate needs to be renewed and returns the reason.
func (s *Scheduler) needsRenewal(cc config.CertConfig, domains []string) (string, error) {
	certPath := filepath.Join(s.storageDir, cc.Primary+".crt")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "certificate file missing or unreadable", nil
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
	certDomains := make([]string, len(cert.DNSNames))
	copy(certDomains, cert.DNSNames)
	sort.Strings(certDomains)

	configDomains := make([]string, len(domains))
	copy(configDomains, domains)
	sort.Strings(configDomains)

	if !reflect.DeepEqual(certDomains, configDomains) {
		return fmt.Sprintf("domains configuration changed (cert: %v, config: %v)", certDomains, configDomains), nil
	}

	return "", nil
}
