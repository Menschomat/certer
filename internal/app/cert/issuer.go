package cert

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns"
	"github.com/go-acme/lego/v5/registration"
)

// CertificateIssuer is the interface for ACME certificate operations.
type CertificateIssuer interface {
	Issue(ctx context.Context, email string, domains []string, filename string, dnsProvider string) (*IssueResult, error)
}

// Issuer manages cert issuance using Lego client.
type Issuer struct {
	caDirURL      string
	storageDir    string
	dnsProvider   string // "cloudflare", "hetzner" or "" (defaults to HTTP-01)
	challengePort string // used if dnsProvider is ""
	acmeProvider  string // "letsencrypt" or "zerossl"
	eabKid        string // Key ID for ACME external account binding
	eabHmac       string // HMAC key for ACME external account binding
	dnsResolvers  []string
}

// NewIssuer creates a new Issuer instance.
func NewIssuer(caDirURL, storageDir, dnsProvider, challengePort, acmeProvider, eabKid, eabHmac string, dnsResolvers []string) *Issuer {
	return &Issuer{
		caDirURL:      caDirURL,
		storageDir:    storageDir,
		dnsProvider:   dnsProvider,
		challengePort: challengePort,
		acmeProvider:  acmeProvider,
		eabKid:        eabKid,
		eabHmac:       eabHmac,
		dnsResolvers:  dnsResolvers,
	}
}

// IssueResult holds the certificate and private key bytes.
type IssueResult struct {
	Domain            string
	CertURL           string
	CertStableURL     string
	PrivateKey        []byte
	Certificate       []byte
	IssuerCertificate []byte
}

// Issue requests a certificate for a list of domains from the ACME CA server.
func (i *Issuer) Issue(ctx context.Context, email string, domains []string, filename string, dnsProvider string) (*IssueResult, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains provided for certificate issuance")
	}
	primaryDomain := domains[0]

	user, err := NewUser(email)
	if err != nil {
		return nil, fmt.Errorf("failed to create acme user: %w", err)
	}

	config := lego.NewConfig(user)
	config.CADirURL = i.caDirURL

	if len(i.dnsResolvers) > 0 {
		dnsClient := dns01.NewClient(&dns01.Options{
			RecursiveNameservers: i.dnsResolvers,
		})
		dns01.SetDefaultClient(dnsClient)
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create acme client: %w", err)
	}

	// Setup DNS-01 or HTTP-01 challenge provider
	providerToUse := dnsProvider
	if providerToUse == "" {
		providerToUse = i.dnsProvider
	}
	if err := i.setupChallengeProvider(client, providerToUse); err != nil {
		return nil, err
	}

	// Register ACME account
	reg, err := i.registerUser(ctx, client, email)
	if err != nil {
		return nil, err
	}
	user.Registration = reg

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
		KeyType: certcrypto.EC256,
	}
	resource, err := client.Certificate.Obtain(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain cert: %w", err)
	}

	if i.storageDir != "" {
		err = i.saveCertificates(filename, resource)
		if err != nil {
			return nil, fmt.Errorf("failed to save certs: %w", err)
		}
	}

	return &IssueResult{
		Domain:            primaryDomain,
		CertURL:           resource.CertURL,
		CertStableURL:     resource.CertStableURL,
		PrivateKey:        resource.PrivateKey,
		Certificate:       resource.Certificate,
		IssuerCertificate: resource.IssuerCertificate,
	}, nil
}

func (i *Issuer) setupChallengeProvider(client *lego.Client, dnsProvider string) error {
	if dnsProvider == "" {
		// Fallback to HTTP-01
		port := i.challengePort
		if port == "" {
			port = "5002"
		}
		err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", port))
		if err != nil {
			return fmt.Errorf("failed to set http-01 challenge: %w", err)
		}
		return nil
	}

	// Dynamically initialize any of the 80+ Lego DNS providers by name
	provider, err := dns.NewDNSChallengeProviderByName(dnsProvider)
	if err != nil {
		return fmt.Errorf("failed to initialize dns provider %q: %w", dnsProvider, err)
	}

	err = client.Challenge.SetDNS01Provider(&syncProvider{provider: provider})
	if err != nil {
		return fmt.Errorf("failed to set dns challenge for provider %q: %w", dnsProvider, err)
	}
	return nil
}

func (i *Issuer) registerUser(ctx context.Context, client *lego.Client, email string) (*acme.ExtendedAccount, error) {
	if i.eabKid != "" && i.eabHmac != "" {
		reg, err := client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  i.eabKid,
			HmacEncoded:          i.eabHmac,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to register user with EAB: %w", err)
		}
		return reg, nil
	}

	if i.acmeProvider == "zerossl" {
		reg, err := registration.RegisterWithZeroSSL(ctx, client.Registration, email)
		if err != nil {
			return nil, fmt.Errorf("failed to register user with ZeroSSL: %w", err)
		}
		return reg, nil
	}

	reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register user: %w", err)
	}
	return reg, nil
}

func (i *Issuer) saveCertificates(domain string, resource *certificate.Resource) error {
	err := os.MkdirAll(i.storageDir, 0755)
	if err != nil {
		return err
	}

	certPath := filepath.Join(i.storageDir, domain+".crt")
	keyPath := filepath.Join(i.storageDir, domain+".key")

	err = os.WriteFile(certPath, resource.Certificate, 0600)
	if err != nil {
		return err
	}

	err = os.WriteFile(keyPath, resource.PrivateKey, 0600)
	if err != nil {
		return err
	}

	return nil
}

type syncProvider struct {
	mu       sync.Mutex
	provider challenge.Provider
}

func (s *syncProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.provider.Present(ctx, domain, token, keyAuth)
}

func (s *syncProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.provider.CleanUp(ctx, domain, token, keyAuth)
}

func (s *syncProvider) Timeout() (timeout, interval time.Duration) {
	if pt, ok := s.provider.(challenge.ProviderTimeout); ok {
		return pt.Timeout()
	}
	return 60 * time.Second, 2 * time.Second
}
