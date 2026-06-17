package cert

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/providers/dns/hetzner"
	"github.com/go-acme/lego/v5/registration"
)

// CertificateIssuer is the interface for ACME certificate operations.
type CertificateIssuer interface {
	Issue(ctx context.Context, email string, domains []string) (*IssueResult, error)
}

// Issuer manages cert issuance using Lego client.
type Issuer struct {
	caDirURL      string
	storageDir    string
	dnsProvider   string // "cloudflare", "hetzner" or "" (defaults to HTTP-01)
	challengePort string // used if dnsProvider is ""
}

// NewIssuer creates a new Issuer instance.
func NewIssuer(caDirURL, storageDir, dnsProvider, challengePort string) *Issuer {
	return &Issuer{
		caDirURL:      caDirURL,
		storageDir:    storageDir,
		dnsProvider:   dnsProvider,
		challengePort: challengePort,
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
func (i *Issuer) Issue(ctx context.Context, email string, domains []string) (*IssueResult, error) {
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

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create acme client: %w", err)
	}

	// Setup DNS-01 or HTTP-01 challenge provider
	switch i.dnsProvider {
	case "cloudflare":
		provider, err := cloudflare.NewDNSProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize cloudflare provider: %w", err)
		}
		err = client.Challenge.SetDNS01Provider(provider)
		if err != nil {
			return nil, fmt.Errorf("failed to set cloudflare dns challenge: %w", err)
		}
	case "hetzner":
		provider, err := hetzner.NewDNSProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize hetzner provider: %w", err)
		}
		err = client.Challenge.SetDNS01Provider(provider)
		if err != nil {
			return nil, fmt.Errorf("failed to set hetzner dns challenge: %w", err)
		}
	default:
		// Fallback to HTTP-01
		port := i.challengePort
		if port == "" {
			port = "5002"
		}
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", port))
		if err != nil {
			return nil, fmt.Errorf("failed to set http-01 challenge: %w", err)
		}
	}

	reg, err := client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register user: %w", err)
	}
	user.Registration = reg

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	resource, err := client.Certificate.Obtain(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain cert: %w", err)
	}

	if i.storageDir != "" {
		err = i.saveCertificates(primaryDomain, resource)
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
