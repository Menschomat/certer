package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMakeTLSConfig_HotReloading(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fallbackCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate fallback cert: %v", err)
	}

	sslCertID := "test-cert-id"
	tlsConfig := makeTLSConfig(tmpDir, sslCertID, fallbackCert)

	// 1. Initially, cert files do not exist, so GetCertificate must return fallbackCert
	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if !reflect.DeepEqual(cert.Certificate, fallbackCert.Certificate) {
		t.Errorf("Expected fallback certificate, got a different certificate")
	}

	// 2. Now write a new valid certificate to disk under the specified config ID
	realCertSource, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("Failed to generate real test cert: %v", err)
	}

	certPath := filepath.Join(tmpDir, sslCertID+".crt")
	keyPath := filepath.Join(tmpDir, sslCertID+".key")

	// Write certificate file
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	for _, certBytes := range realCertSource.Certificate {
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	}
	certOut.Close()

	// Write key file
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	privKey, err := x509.MarshalECPrivateKey(realCertSource.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKey})
	keyOut.Close()

	// 3. Call GetCertificate again - it should now dynamically pick up the new certificate from disk
	certReloaded, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate failed after write: %v", err)
	}
	if reflect.DeepEqual(certReloaded.Certificate, fallbackCert.Certificate) {
		t.Errorf("Expected reloaded certificate from disk, but got the fallback certificate")
	}

	// Double check we got the actual realCertSource cert bytes
	if !reflect.DeepEqual(certReloaded.Certificate[0], realCertSource.Certificate[0]) {
		t.Errorf("Reloaded certificate bytes do not match expected written certificate")
	}
}
