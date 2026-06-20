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
	"sync"
	"testing"
	"time"

	"cert-central/internal/app/config"
)

type MockIssuer struct {
	mu            sync.RWMutex
	CalledCount   int
	CalledEmail   string
	CalledDomains [][]string
	Result        *IssueResult
	Err           error
}

func (m *MockIssuer) Issue(ctx context.Context, email string, domains []string, filename string) (*IssueResult, error) {
	m.mu.Lock()
	m.CalledCount++
	m.CalledEmail = email
	m.CalledDomains = append(m.CalledDomains, domains)
	m.mu.Unlock()
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

	err = os.MkdirAll(dir, 0755)
	if err != nil {
		t.Fatalf("Failed to create dir: %v", err)
	}

	certOut, err := os.Create(filepath.Join(dir, id+".crt"))
	if err != nil {
		t.Fatalf("Failed to open cert file: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.OpenFile(filepath.Join(dir, id+".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("Failed to open key file: %v", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
}

func TestScheduler_CheckAndRenew(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	email := "user@example.com"
	certsConfig := []config.CertConfig{
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

	t.Run("No Certificates Exist", func(t *testing.T) {
		mock := &MockIssuer{}
		s := NewScheduler(mock, email, certsConfig, tmpDir, 30, 24)
		err := s.CheckAndRenew(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRenew failed: %v", err)
		}

		if mock.CalledCount != 2 {
			t.Errorf("Expected Issue() to be called twice, got %d", mock.CalledCount)
		}
	})

	t.Run("One Valid, One Expiring", func(t *testing.T) {
		mock := &MockIssuer{}
		createTestCertificate(t, tmpDir, "id-example", "example.com", []string{"*.example.com"}, time.Now().Add(60*24*time.Hour))
		createTestCertificate(t, tmpDir, "id-other", "other.com", []string{"*.other.com"}, time.Now().Add(10*24*time.Hour))

		s := NewScheduler(mock, email, certsConfig, tmpDir, 30, 24)
		err := s.CheckAndRenew(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRenew failed: %v", err)
		}

		if mock.CalledCount != 1 {
			t.Errorf("Expected Issue() to be called once, got %d", mock.CalledCount)
		}
		if mock.CalledDomains[0][0] != "other.com" {
			t.Errorf("Expected other.com to be renewed, got %v", mock.CalledDomains[0])
		}
	})

	t.Run("Valid Certificate, Missing Private Key", func(t *testing.T) {
		mock := &MockIssuer{}
		// Clean up files first
		os.Remove(filepath.Join(tmpDir, "id-example.crt"))
		os.Remove(filepath.Join(tmpDir, "id-example.key"))
		os.Remove(filepath.Join(tmpDir, "id-other.crt"))
		os.Remove(filepath.Join(tmpDir, "id-other.key"))

		createTestCertificate(t, tmpDir, "id-example", "example.com", []string{"*.example.com"}, time.Now().Add(60*24*time.Hour))
		createTestCertificate(t, tmpDir, "id-other", "other.com", []string{"*.other.com"}, time.Now().Add(60*24*time.Hour))

		// Delete only the private key for id-example
		if err := os.Remove(filepath.Join(tmpDir, "id-example.key")); err != nil {
			t.Fatalf("Failed to remove mock key: %v", err)
		}

		s := NewScheduler(mock, email, certsConfig, tmpDir, 30, 24)
		err := s.CheckAndRenew(context.Background())
		if err != nil {
			t.Fatalf("CheckAndRenew failed: %v", err)
		}

		if mock.CalledCount != 1 {
			t.Errorf("Expected Issue() to be called once, got %d", mock.CalledCount)
		}
		if len(mock.CalledDomains) > 0 && mock.CalledDomains[0][0] != "example.com" {
			t.Errorf("Expected example.com to be renewed, got %v", mock.CalledDomains[0])
		}
	})

	t.Run("Cleanup Unused Certificates", func(t *testing.T) {
		mock := &MockIssuer{}
		
		// Create certificate and key files
		createTestCertificate(t, tmpDir, "id-example", "example.com", []string{"*.example.com"}, time.Now().Add(60*24*time.Hour))
		
		// Create unused files
		unusedCertPath := filepath.Join(tmpDir, "id-unused.crt")
		unusedKeyPath := filepath.Join(tmpDir, "id-unused.key")
		randomFilePath := filepath.Join(tmpDir, "random.txt")
		
		if err := os.WriteFile(unusedCertPath, []byte("mock-cert"), 0600); err != nil {
			t.Fatalf("failed to create unused cert: %v", err)
		}
		if err := os.WriteFile(unusedKeyPath, []byte("mock-key"), 0600); err != nil {
			t.Fatalf("failed to create unused key: %v", err)
		}
		if err := os.WriteFile(randomFilePath, []byte("hello world"), 0600); err != nil {
			t.Fatalf("failed to create random file: %v", err)
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

	s.ReloadConfig(context.Background(), newCerts)

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

	if calledCount != 1 {
		t.Errorf("Expected issue to be called once on reload, got %d", calledCount)
	}
	if calledDomain != "newdomain.com" {
		t.Errorf("Expected newdomain.com to be checked, got %q", calledDomain)
	}
}

