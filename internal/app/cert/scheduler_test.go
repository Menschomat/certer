package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"certer/internal/app/config"
)

type MockIssuer struct {
	mu                 sync.RWMutex
	CalledCount        int
	CalledEmail        string
	CalledDomains      [][]string
	CalledDNSProviders []string
	Result             *IssueResult
	Err                error
	HasCanceledContext bool
}

func (m *MockIssuer) Issue(ctx context.Context, email string, domains []string, filename string, dnsProvider string) (*IssueResult, error) {
	m.mu.Lock()
	m.CalledCount++
	m.CalledEmail = email
	m.CalledDomains = append(m.CalledDomains, domains)
	m.CalledDNSProviders = append(m.CalledDNSProviders, dnsProvider)
	if ctx.Err() != nil {
		m.HasCanceledContext = true
	}
	m.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return &IssueResult{
		Domain:      domains[0],
		Certificate: []byte("mock-cert"),
		PrivateKey:  []byte("mock-key"),
	}, m.Err
}

func createTestCertificate(t *testing.T, dir string, id string, domain string, sans []string, notAfter time.Time) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	dnsNames := append([]string{domain}, sans...)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create(filepath.Join(dir, id+".crt"))
	if err != nil {
		t.Fatalf("Failed to open crt file for writing: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.Create(filepath.Join(dir, id+".key"))
	if err != nil {
		t.Fatalf("Failed to open key file for writing: %v", err)
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	keyOut.Close()
}

func TestScheduler_CheckAndRenew(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scheduler-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mock := &MockIssuer{}
	email := "admin@example.com"
	certs := []config.CertConfig{
		{
			ID:      "id-example",
			Primary: "example.com",
			Sans:    []string{"*.example.com"},
		},
		{
			ID:      "id-other",
			Primary: "other.com",
			Sans:    []string{"*.other.com"},
		},
	}

	s := NewScheduler(mock, email, certs, tmpDir, 30, 24)

	t.Run("No_Certificates_Exist", func(t *testing.T) {
		err := s.CheckAndRenew(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRenew failed: %v", err)
		}

		mock.mu.RLock()
		calledCount := mock.CalledCount
		mock.mu.RUnlock()
		if calledCount != 2 {
			t.Errorf("Expected Issue to be called 2 times, got %d", calledCount)
		}
	})

	t.Run("One_Valid,_One_Expiring", func(t *testing.T) {
		mock.mu.Lock()
		mock.CalledCount = 0
		mock.CalledDomains = nil
		mock.mu.Unlock()

		// Create a valid certificate (expires in 1 year) for id-example
		createTestCertificate(t, tmpDir, "id-example", "example.com", []string{"*.example.com"}, time.Now().AddDate(1, 0, 0))

		// Create an expiring certificate (expires in 10 hours) for id-other
		createTestCertificate(t, tmpDir, "id-other", "other.com", []string{"*.other.com"}, time.Now().Add(10*time.Hour))

		err := s.CheckAndRenew(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRenew failed: %v", err)
		}

		mock.mu.RLock()
		calledCount := mock.CalledCount
		mock.mu.RUnlock()
		if calledCount != 1 {
			t.Errorf("Expected Issue to be called 1 time (only for expiring cert), got %d", calledCount)
		}
	})

	t.Run("Valid_Certificate,_Missing_Private_Key", func(t *testing.T) {
		mock.mu.Lock()
		mock.CalledCount = 0
		mock.CalledDomains = nil
		mock.mu.Unlock()

		// Keep id-example valid cert but delete its private key
		os.Remove(filepath.Join(tmpDir, "id-example.key"))

		// Ensure id-other has both cert and key and is valid (expires in 1 year)
		createTestCertificate(t, tmpDir, "id-other", "other.com", []string{"*.other.com"}, time.Now().AddDate(1, 0, 0))

		err := s.CheckAndRenew(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRenew failed: %v", err)
		}

		mock.mu.RLock()
		calledCount := mock.CalledCount
		mock.mu.RUnlock()
		if calledCount != 1 {
			t.Errorf("Expected Issue to be called 1 time (only for missing private key cert), got %d", calledCount)
		}
	})

	t.Run("Cleanup_Unused_Certificates", func(t *testing.T) {
		mock.mu.Lock()
		mock.CalledCount = 0
		mock.CalledDomains = nil
		mock.mu.Unlock()

		// Ensure id-example is valid (cert + key)
		createTestCertificate(t, tmpDir, "id-example", "example.com", []string{"*.example.com"}, time.Now().AddDate(1, 0, 0))

		// Create stray cert/key files on disk for an "id-other" configuration
		createTestCertificate(t, tmpDir, "id-other", "other.com", []string{"*.other.com"}, time.Now().AddDate(1, 0, 0))

		// Create stray cert/key files on disk for a completely unconfigured ID "id-unused"
		createTestCertificate(t, tmpDir, "id-unused", "unused.com", []string{"*.unused.com"}, time.Now().AddDate(1, 0, 0))
		unusedCertPath := filepath.Join(tmpDir, "id-unused.crt")
		unusedKeyPath := filepath.Join(tmpDir, "id-unused.key")

		// Create an unrelated file that should not be touched
		randomFilePath := filepath.Join(tmpDir, "random.txt")
		if err := os.WriteFile(randomFilePath, []byte("don't delete"), 0644); err != nil {
			t.Fatalf("failed to write random file: %v", err)
		}

		// Configure only example.com (excluding unused.com)
		singleCertConfig := []config.CertConfig{
			{
				ID:      "id-example",
				Primary: "example.com",
				Sans:    []string{"*.example.com"},
			},
		}

		s := NewScheduler(mock, email, singleCertConfig, tmpDir, 30, 24)
		err := s.CheckAndRenew(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRenew failed: %v", err)
		}

		// example.com files should still exist
		if _, err := os.Stat(filepath.Join(tmpDir, "id-example.crt")); os.IsNotExist(err) {
			t.Errorf("id-example.crt should not have been deleted")
		}
		if _, err := os.Stat(filepath.Join(tmpDir, "id-example.key")); os.IsNotExist(err) {
			t.Errorf("id-example.key should not have been deleted")
		}

		// random.txt should still exist (unrelated extension)
		if _, err := os.Stat(randomFilePath); os.IsNotExist(err) {
			t.Errorf("random.txt should not have been deleted")
		}

		// unused.com files should have been deleted
		if _, err := os.Stat(unusedCertPath); !os.IsNotExist(err) {
			t.Errorf("id-unused.crt should have been cleaned up")
		}
		if _, err := os.Stat(unusedKeyPath); !os.IsNotExist(err) {
			t.Errorf("id-unused.key should have been cleaned up")
		}
	})
}

func TestScheduler_ReloadConfig(t *testing.T) {
	mock := &MockIssuer{}
	s := NewScheduler(mock, "user@example.com", nil, "", 30, 24)

	newCerts := []config.CertConfig{
		{
			ID:      "id-new",
			Primary: "newdomain.com",
			Sans:    []string{"www.newdomain.com"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel the context immediately

	s.ReloadConfig(ctx, newCerts)

	// Since ReloadConfig runs CheckAndRenew in a background goroutine, we need to wait a brief moment for it to run.
	time.Sleep(100 * time.Millisecond)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.certificates) != 1 || s.certificates[0].Primary != "newdomain.com" {
		t.Errorf("Expected certificates to be reloaded, got %v", s.certificates)
	}

	mock.mu.RLock()
	calledCount := mock.CalledCount
	var calledDomain string
	if len(mock.CalledDomains) > 0 && len(mock.CalledDomains[0]) > 0 {
		calledDomain = mock.CalledDomains[0][0]
	}
	mock.mu.RUnlock()

	// If context cancellation wasn't detached, calledCount would be 0 or dynamic renewal would fail.
	// We want calledCount to be 1 and calledDomain to match, which fails if the Issuer returns context.Canceled error.
	if calledCount != 1 {
		t.Errorf("Expected issue to be called once on reload, got %d", calledCount)
	}
	if calledDomain != "newdomain.com" {
		t.Errorf("Expected newdomain.com to be checked, got %q", calledDomain)
	}
	mock.mu.RLock()
	hasCanceled := mock.HasCanceledContext
	mock.mu.RUnlock()
	if hasCanceled {
		t.Errorf("Expected ReloadConfig to run with a non-canceled context, but the context was canceled")
	}
}

func TestScheduler_DNSProviderOverride(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scheduler-dns-override-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mock := &MockIssuer{}
	email := "admin@example.com"
	certs := []config.CertConfig{
		{
			ID:          "id-hetzner",
			Primary:     "hetznerdomain.com",
			Sans:        []string{"*.hetznerdomain.com"},
			DNSProvider: "hetzner",
		},
		{
			ID:          "id-default",
			Primary:     "defaultdomain.com",
			Sans:        []string{"*.defaultdomain.com"},
			DNSProvider: "", // Should use default (empty)
		},
	}

	s := NewScheduler(mock, email, certs, tmpDir, 30, 24)

	err = s.CheckAndRenew(context.Background())
	if err != nil {
		t.Fatalf("CheckAndRenew failed: %v", err)
	}

	mock.mu.RLock()
	calledCount := mock.CalledCount
	calledProviders := make([]string, len(mock.CalledDNSProviders))
	copy(calledProviders, mock.CalledDNSProviders)
	mock.mu.RUnlock()

	if calledCount != 2 {
		t.Errorf("Expected Issue to be called 2 times, got %d", calledCount)
	}

	expectedProviders := []string{"hetzner", ""}
	if !reflect.DeepEqual(calledProviders, expectedProviders) {
		t.Errorf("Expected called DNS providers %v, got %v", expectedProviders, calledProviders)
	}
}

