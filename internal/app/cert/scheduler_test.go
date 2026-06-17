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
	"testing"
	"time"

	"cert-central/internal/app/config"
)

type MockIssuer struct {
	CalledCount   int
	CalledEmail   string
	CalledDomains [][]string
	Result        *IssueResult
	Err           error
}

func (m *MockIssuer) Issue(ctx context.Context, email string, domains []string) (*IssueResult, error) {
	m.CalledCount++
	m.CalledEmail = email
	m.CalledDomains = append(m.CalledDomains, domains)
	return &IssueResult{
		Domain:      domains[0],
		Certificate: []byte("mock-cert"),
		PrivateKey:  []byte("mock-key"),
	}, m.Err
}

func createTestCertificate(t *testing.T, dir string, domain string, sans []string, notAfter time.Time) {
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

	certOut, err := os.Create(filepath.Join(dir, domain+".crt"))
	if err != nil {
		t.Fatalf("Failed to open cert file: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.OpenFile(filepath.Join(dir, domain+".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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
			Primary: "example.com",
			Sans:    []string{"*.example.com"},
		},
		{
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
		createTestCertificate(t, tmpDir, "example.com", []string{"*.example.com"}, time.Now().Add(60*24*time.Hour))
		createTestCertificate(t, tmpDir, "other.com", []string{"*.other.com"}, time.Now().Add(10*24*time.Hour))

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
}
