package cert

import (
	"context"
	"sync"
	"testing"
)

func TestNewIssuer(t *testing.T) {
	caDirURL := "https://acme-staging.example.com"
	storageDir := "./test_certs"
	dnsProvider := "cloudflare"
	challengePort := "80"
	acmeProvider := "zerossl"
	eabKid := "kid123"
	eabHmac := "hmac456"

	issuer := NewIssuer(caDirURL, storageDir, dnsProvider, challengePort, acmeProvider, eabKid, eabHmac, nil)

	if issuer.caDirURL != caDirURL {
		t.Errorf("Expected caDirURL %q, got %q", caDirURL, issuer.caDirURL)
	}
	if issuer.storageDir != storageDir {
		t.Errorf("Expected storageDir %q, got %q", storageDir, issuer.storageDir)
	}
	if issuer.dnsProvider != dnsProvider {
		t.Errorf("Expected dnsProvider %q, got %q", dnsProvider, issuer.dnsProvider)
	}
	if issuer.challengePort != challengePort {
		t.Errorf("Expected challengePort %q, got %q", challengePort, issuer.challengePort)
	}
	if issuer.acmeProvider != acmeProvider {
		t.Errorf("Expected acmeProvider %q, got %q", acmeProvider, issuer.acmeProvider)
	}
	if issuer.eabKid != eabKid {
		t.Errorf("Expected eabKid %q, got %q", eabKid, issuer.eabKid)
	}
	if issuer.eabHmac != eabHmac {
		t.Errorf("Expected eabHmac %q, got %q", eabHmac, issuer.eabHmac)
	}
	if len(issuer.dnsResolvers) != 0 {
		t.Errorf("Expected empty dnsResolvers, got %v", issuer.dnsResolvers)
	}
}

type mockProvider struct {
	mu           sync.Mutex
	presentCalls int
	cleanupCalls int
}

func (m *mockProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	m.mu.Lock()
	m.presentCalls++
	m.mu.Unlock()
	return nil
}

func (m *mockProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	m.mu.Lock()
	m.cleanupCalls++
	m.mu.Unlock()
	return nil
}

func TestSyncProvider(t *testing.T) {
	mock := &mockProvider{}
	wrapped := &syncProvider{provider: mock}

	ctx := context.Background()

	if err := wrapped.Present(ctx, "example.com", "tok", "key"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err := wrapped.CleanUp(ctx, "example.com", "tok", "key"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if mock.presentCalls != 1 {
		t.Errorf("Expected 1 present call, got %d", mock.presentCalls)
	}
	if mock.cleanupCalls != 1 {
		t.Errorf("Expected 1 cleanup call, got %d", mock.cleanupCalls)
	}
}
