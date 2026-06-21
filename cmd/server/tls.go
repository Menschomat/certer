package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// generateSelfSignedCert generates a temporary in-memory self-signed ECDSA certificate
// for use on boot when the real certificate is not yet ready or configured.
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Certer Temp Authority"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// makeTLSConfig returns a tls.Config with GetCertificate callback configured for dynamic hot-reloading.
func makeTLSConfig(certStorageDir, sslCertID string, fallbackCert tls.Certificate) *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if sslCertID != "" {
				certPath := filepath.Join(certStorageDir, sslCertID+".crt")
				keyPath := filepath.Join(certStorageDir, sslCertID+".key")

				if _, errCert := os.Stat(certPath); errCert == nil {
					if _, errKey := os.Stat(keyPath); errKey == nil {
						if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
							return &cert, nil
						}
					}
				}
			}
			return &fallbackCert, nil
		},
	}
}
