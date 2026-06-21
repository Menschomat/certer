package cert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/go-acme/lego/v5/lego"
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

func TestSetupChallengeProvider(t *testing.T) {
	// Start a mock HTTPS ACME directory server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"newNonce": "https://localhost/new-nonce",
			"newAccount": "https://localhost/new-account",
			"newOrder": "https://localhost/new-order",
			"newAuthz": "https://localhost/new-authz",
			"revokeCert": "https://localhost/revoke-cert",
			"meta": {
				"termsOfService": "https://localhost/terms"
			}
		}`))
	}))
	defer server.Close()

	user, err := NewUser("test@example.com")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	config := lego.NewConfig(user)
	config.CADirURL = server.URL
	config.HTTPClient = server.Client()
	client, err := lego.NewClient(config)
	if err != nil {
		t.Fatalf("Failed to create lego client: %v", err)
	}

	issuer := NewIssuer(server.URL, "./test_certs", "", "5002", "letsencrypt", "", "", nil)
	
	// 1. Fallback to HTTP-01 (should succeed)
	err = issuer.setupChallengeProvider(client, "")
	if err != nil {
		t.Errorf("Expected fallback to HTTP-01 to succeed, got error: %v", err)
	}

	// 2. Invalid Provider (should return error)
	err = issuer.setupChallengeProvider(client, "invalid_dns_provider")
	if err == nil {
		t.Error("Expected error for invalid DNS provider, got nil")
	}

	// 3. Valid Provider (Missing Credentials) -> should fail
	os.Unsetenv("CF_DNS_API_TOKEN")
	os.Unsetenv("CLOUDFLARE_DNS_API_TOKEN")
	os.Unsetenv("CF_API_KEY")
	os.Unsetenv("CLOUDFLARE_API_KEY")
	os.Unsetenv("CF_API_EMAIL")
	os.Unsetenv("CLOUDFLARE_EMAIL")
	err = issuer.setupChallengeProvider(client, "cloudflare")
	if err == nil {
		t.Error("Expected error for cloudflare due to missing credentials, got nil")
	}

	// 4. Valid Provider (With Credentials) -> should succeed
	t.Setenv("CF_DNS_API_TOKEN", "mock-token-here")
	err = issuer.setupChallengeProvider(client, "cloudflare")
	if err != nil {
		t.Errorf("Expected cloudflare initialization to succeed with env, got error: %v", err)
	}
}

