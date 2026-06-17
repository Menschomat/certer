package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"cert-central/internal/app/config"
)

func TestHandleHealth(t *testing.T) {
	server := NewServer("", nil, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	res, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK; got %v", res.Status)
	}
}

func TestHandleHello(t *testing.T) {
	server := NewServer("", nil, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	res, err := http.Get(ts.URL + "/api/v1/hello")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK; got %v", res.Status)
	}
}

func TestHandleGetCertificates_Authentication(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "api-cert-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certsConfig := []config.CertConfig{
		{
			Primary: "menscho.space",
			Sans:    []string{"*.menscho.space"},
		},
		{
			Primary: "weihrauchphoto.de",
			Sans:    []string{"*.weihrauchphoto.de"},
		},
		{
			Primary: "bly.li",
			Sans:    []string{"*.bly.li"},
		},
	}

	hashedToken, err := GenerateArgon2idHash("blabliblub")
	if err != nil {
		t.Fatalf("Failed to generate test token hash: %v", err)
	}

	apiKeys := []config.APIKeyConfig{
		{
			Token:          hashedToken,
			AllowedDomains: []string{"menscho.space", "weihrauchphoto.de"},
		},
	}

	for _, cc := range certsConfig {
		err := os.WriteFile(filepath.Join(tmpDir, cc.Primary+".crt"), []byte("cert-for-"+cc.Primary), 0644)
		if err != nil {
			t.Fatalf("Failed to write mock cert file: %v", err)
		}
		err = os.WriteFile(filepath.Join(tmpDir, cc.Primary+".key"), []byte("key-for-"+cc.Primary), 0644)
		if err != nil {
			t.Fatalf("Failed to write mock key file: %v", err)
		}
	}

	server := NewServer(tmpDir, certsConfig, apiKeys)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	t.Run("Missing Authorization Header (401)", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/api/v1/certificates")
		if err != nil {
			t.Fatalf("Failed request: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %v", res.Status)
		}
	})

	t.Run("Invalid Token (401)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates", nil)
		req.Header.Set("Authorization", "Bearer invalidtoken")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed request: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %v", res.Status)
		}
	})

	t.Run("Valid Token - Allowed Domains Only (200)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates", nil)
		req.Header.Set("Authorization", "Bearer blabliblub")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Failed request: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %v", res.Status)
		}

		var resp []CertificateResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(resp) != 2 {
			t.Fatalf("Expected 2 certificates, got %d", len(resp))
		}

		domainsFound := make(map[string]bool)
		for _, certItem := range resp {
			domainsFound[certItem.Domain] = true
			if certItem.Domain == "bly.li" {
				t.Error("Unauthorized domain 'bly.li' returned in response!")
			}
		}

		if !domainsFound["menscho.space"] || !domainsFound["weihrauchphoto.de"] {
			t.Errorf("Expected domains 'menscho.space' and 'weihrauchphoto.de' to be present, got: %v", domainsFound)
		}
	})
}
