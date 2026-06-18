package cert

import (
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

	issuer := NewIssuer(caDirURL, storageDir, dnsProvider, challengePort, acmeProvider, eabKid, eabHmac)

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
}
