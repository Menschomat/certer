package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certer/internal/app/config"
)

func createAPITestCertificate(t *testing.T, dir, id, domain string, sans []string, notBefore, notAfter time.Time, writeKey bool) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: domain},
		Issuer:                pkix.Name{CommonName: "Certer Test CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string{domain}, sans...),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	certFile, err := os.Create(filepath.Join(dir, id+".crt"))
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("Failed to encode cert: %v", err)
	}
	if err := certFile.Close(); err != nil {
		t.Fatalf("Failed to close cert file: %v", err)
	}

	if !writeKey {
		return
	}
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	keyFile, err := os.Create(filepath.Join(dir, id+".key"))
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("Failed to encode key: %v", err)
	}
	if err := keyFile.Close(); err != nil {
		t.Fatalf("Failed to close key file: %v", err)
	}
}

func TestHandleGetCertificates_Authentication(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-cert-tests-*")
	defer cleanup()

	certsConfig := []config.CertConfig{
		{
			ID:      "019035a1-7b00-7521-8280-60b6adbf47eb",
			Primary: "menscho.space",
			Sans:    []string{"*.menscho.space"},
			TeamID:  "system",
		},
		{
			ID:      "019035a1-7b00-7521-8280-60b6adbf47ec",
			Primary: "weihrauchphoto.de",
			Sans:    []string{"*.weihrauchphoto.de"},
			TeamID:  "system",
		},
		{
			ID:      "019035a1-7b00-7521-8280-60b6adbf47ed",
			Primary: "bly.li",
			Sans:    []string{"*.bly.li"},
			TeamID:  "system",
		},
	}

	apiKeys := []config.APIKeyConfig{
		{
			ID:                  "019035a1-7b00-7521-8280-60b6adbf47ee",
			Token:               testAdminHash,
			AllowedCertificates: []string{"019035a1-7b00-7521-8280-60b6adbf47eb", "019035a1-7b00-7521-8280-60b6adbf47ec"},
			AllowedTeams:        []string{"system"},
		},
	}

	for _, cc := range certsConfig {
		err := os.WriteFile(filepath.Join(tmpDir, cc.ID+".crt"), []byte("cert-for-"+cc.Primary), 0644)
		if err != nil {
			t.Fatalf("Failed to write mock cert file: %v", err)
		}
		err = os.WriteFile(filepath.Join(tmpDir, cc.ID+".key"), []byte("key-for-"+cc.Primary), 0644)
		if err != nil {
			t.Fatalf("Failed to write mock key file: %v", err)
		}
	}

	cfg := &config.Config{
		Certificates: certsConfig,
		APIKeys:      apiKeys,
	}
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	t.Run("Missing Authorization Header (401)", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		oldLogger := slog.Default()
		slog.SetDefault(logger)
		defer slog.SetDefault(oldLogger)

		res, err := http.Get(ts.URL + "/api/v1/certificates")
		if err != nil {
			t.Fatalf("Failed request: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized, got %v", res.Status)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, "Unauthorized access attempt: missing token") {
			t.Errorf("Expected log message containing missing token warning, got: %q", logOutput)
		}
	})

	t.Run("Invalid Token (401)", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		oldLogger := slog.Default()
		slog.SetDefault(logger)
		defer slog.SetDefault(oldLogger)

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

		logOutput := buf.String()
		if !strings.Contains(logOutput, "Unauthorized access attempt: invalid token") {
			t.Errorf("Expected log message containing invalid token warning, got: %q", logOutput)
		}
		if !strings.Contains(logOutput, `"token_prefix":"inval"`) {
			t.Errorf("Expected log message to contain token prefix 'inval', got: %q", logOutput)
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
			expectedCertFilename := certItem.Domain + ".crt"
			expectedKeyFilename := certItem.Domain + ".key"
			if certItem.CertFilename != expectedCertFilename {
				t.Errorf("Expected CertFilename %q, got %q", expectedCertFilename, certItem.CertFilename)
			}
			if certItem.KeyFilename != expectedKeyFilename {
				t.Errorf("Expected KeyFilename %q, got %q", expectedKeyFilename, certItem.KeyFilename)
			}
		}

		if !domainsFound["menscho.space"] || !domainsFound["weihrauchphoto.de"] {
			t.Errorf("Expected domains 'menscho.space' and 'weihrauchphoto.de' to be present, got: %v", domainsFound)
		}
	})
}

func TestControlPlaneAPI_Certificates(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "control-plane-api-cert-tests-*")
	defer cleanup()
	configPath := os.Getenv("CONFIG_PATH")

	initialConfig := &config.Config{
		Port: "8080",
		APIKeys: []config.APIKeyConfig{
			{
				ID:    "admin-key-id",
				Token: testAdminHash,
				Admin: true,
			},
		},
		Certificates: []config.CertConfig{
			{
				ID:      "example-cert-id",
				Primary: "example.com",
				Sans:    []string{"www.example.com"},
				TeamID:  "team-id-1",
			},
		},
		Teams: []config.TeamConfig{
			{
				ID:          "team-id-1",
				Name:        "Team 1",
				Description: "First test team",
			},
		},
	}
	if err := initialConfig.Save(configPath); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	cfg := config.MustLoad()
	reloader := &MockReloader{}
	server := NewServer(tmpDir, cfg, reloader)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	adminHeader := "Bearer " + testAdminToken
	var newCertID string

	t.Run("GET Certificates Configuration", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/config/certificates", nil)
		req.Header.Set("Authorization", adminHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var certs []config.CertConfig
		if err := json.NewDecoder(res.Body).Decode(&certs); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if len(certs) != 1 || certs[0].Primary != "example.com" || certs[0].ID != "example-cert-id" {
			t.Errorf("Unexpected certificates response: %+v", certs)
		}
	})

	t.Run("POST Certificate Configuration - Success", func(t *testing.T) {
		newCert := config.CertConfig{
			Primary:     "newdomain.com",
			Sans:        []string{"*.newdomain.com"},
			TeamID:      "team-id-1",
			Description: "New Certificate",
			DNSProvider: "hetzner",
		}
		body, _ := json.Marshal(newCert)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/certificates", bytes.NewReader(body))
		req.Header.Set("Authorization", adminHeader)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusCreated {
			t.Errorf("Expected 201 Created, got %d", res.StatusCode)
		}

		var created config.CertConfig
		if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		newCertID = created.ID
		if newCertID == "" {
			t.Errorf("Expected generated UUID in response")
		}
		if created.DNSProvider != "hetzner" {
			t.Errorf("Expected DNSProvider 'hetzner', got %q", created.DNSProvider)
		}

		// Verify reloader was called
		if reloader.CalledCount != 1 {
			t.Errorf("Expected reloader to be called once, got %d", reloader.CalledCount)
		}

		// Verify saved config file has the new certificate
		loadedCfg := config.MustLoad()
		allCerts := loadedCfg.AllCertificates()
		if len(allCerts) != 2 || allCerts[1].Primary != "newdomain.com" || allCerts[1].ID != newCertID || allCerts[1].DNSProvider != "hetzner" {
			t.Errorf("Expected new certificate to be saved on disk with DNS provider, got: %+v", allCerts)
		}
	})

	t.Run("POST Certificate Configuration - Duplicate Allowed", func(t *testing.T) {
		duplicateCert := config.CertConfig{
			Primary: "example.com",
			Sans:    []string{"another.example.com"},
			TeamID:  "team-id-1",
		}
		body, _ := json.Marshal(duplicateCert)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/certificates", bytes.NewReader(body))
		req.Header.Set("Authorization", adminHeader)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusCreated {
			t.Errorf("Expected 201 Created, got %d", res.StatusCode)
		}
	})

	t.Run("PUT Certificate Configuration - Success", func(t *testing.T) {
		updatedCert := config.CertConfig{
			Primary:     "newdomain.com",
			Sans:        []string{"admin.example.com", "mail.example.com"},
			TeamID:      "team-id-1",
			Description: "Updated Description",
			DNSProvider: "cloudflare",
		}
		body, _ := json.Marshal(updatedCert)
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config/certificates/"+newCertID, bytes.NewReader(body))
		req.Header.Set("Authorization", adminHeader)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		loadedCfg := config.MustLoad()
		for _, c := range loadedCfg.AllCertificates() {
			if c.ID == newCertID {
				if len(c.Sans) != 2 || c.Sans[0] != "admin.example.com" || c.Description != "Updated Description" || c.DNSProvider != "cloudflare" {
					t.Errorf("Expected updated SANs, description, and DNSProvider, got %+v", c)
				}
			}
		}
	})

	t.Run("PUT Certificate Configuration - Not Found", func(t *testing.T) {
		updatedCert := config.CertConfig{
			Sans:   []string{"mail.nonexistent.com"},
			TeamID: "team-id-1",
		}
		body, _ := json.Marshal(updatedCert)
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config/certificates/nonexistent-id", bytes.NewReader(body))
		req.Header.Set("Authorization", adminHeader)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 Not Found, got %d", res.StatusCode)
		}
	})

	t.Run("DELETE Certificate Configuration - Success", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/certificates/"+newCertID, nil)
		req.Header.Set("Authorization", adminHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusNoContent {
			t.Errorf("Expected 204 No Content, got %d", res.StatusCode)
		}
	})
}

func TestScopedAdmin_Certificates(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-cert-scoped-*")
	defer cleanup()
	configPath := os.Getenv("CONFIG_PATH")

	hashedScopedAdmin, _ := GenerateArgon2idHash("scoped-admin-token")

	initialConfig := &config.Config{
		APIKeys: []config.APIKeyConfig{
			{
				ID:           "scoped-admin-id",
				Token:        hashedScopedAdmin,
				AllowedTeams: []string{"team-id-1"},
				Admin:        true,
			},
		},
		Teams: []config.TeamConfig{
			{ID: "team-id-1", Name: "Team 1"},
			{ID: "team-id-2", Name: "Team 2"},
		},
	}
	if err := initialConfig.Save(configPath); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	statePath := filepath.Join(tmpDir, "state.json")
	stateData := `{
		"certificates": [
			{
				"id": "cert-team-1",
				"primary": "team1.com",
				"team_id": "team-id-1"
			},
			{
				"id": "cert-team-2",
				"primary": "team2.com",
				"team_id": "team-id-2"
			}
		]
	}`
	if err := os.WriteFile(statePath, []byte(stateData), 0644); err != nil {
		t.Fatalf("Failed to write state: %v", err)
	}

	cfg := config.MustLoad()
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	authHeader := "Bearer scoped-admin-token"

	t.Run("List Filter", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/config/certificates", nil)
		req.Header.Set("Authorization", authHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var certs []config.CertConfig
		if err := json.NewDecoder(res.Body).Decode(&certs); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if len(certs) != 1 {
			t.Fatalf("Expected exactly 1 certificate, got %d", len(certs))
		}
		if certs[0].ID != "cert-team-1" {
			t.Errorf("Expected cert-team-1, got %q", certs[0].ID)
		}
	})

	t.Run("Unauthorized Create", func(t *testing.T) {
		newCert := config.CertConfig{
			Primary: "unauthorized.com",
			TeamID:  "team-id-2",
		}
		body, _ := json.Marshal(newCert)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/certificates", bytes.NewReader(body))
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", res.StatusCode)
		}
	})

	t.Run("Authorized Create", func(t *testing.T) {
		newCert := config.CertConfig{
			Primary: "authorized.com",
			TeamID:  "team-id-1",
		}
		body, _ := json.Marshal(newCert)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/certificates", bytes.NewReader(body))
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusCreated {
			t.Errorf("Expected 201 Created, got %d", res.StatusCode)
		}
	})

	t.Run("Unauthorized Delete", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/certificates/cert-team-2", nil)
		req.Header.Set("Authorization", authHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 Not Found, got %d", res.StatusCode)
		}
	})

	t.Run("Unauthorized Team Reassignment", func(t *testing.T) {
		updatePayload := config.CertConfig{
			Primary: "team1.com",
			TeamID:  "team-id-2",
		}
		body, _ := json.Marshal(updatePayload)
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config/certificates/cert-team-1", bytes.NewReader(body))
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", res.StatusCode)
		}
	})
}

func TestDefaultDeny_UnassignedCertificates(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-cert-deny-*")
	defer cleanup()
	configPath := os.Getenv("CONFIG_PATH")

	hashedFetchTokenEmpty, _ := GenerateArgon2idHash("fetch-token-empty")
	hashedFetchTokenSystem, _ := GenerateArgon2idHash("fetch-token-system")

	initialConfig := &config.Config{
		APIKeys: []config.APIKeyConfig{
			{
				ID:                  "fetch-key-empty",
				Token:               hashedFetchTokenEmpty,
				AllowedCertificates: []string{"cert-unassigned"},
				AllowedTeams:        []string{},
				Admin:               false,
			},
			{
				ID:                  "fetch-key-system",
				Token:               hashedFetchTokenSystem,
				AllowedCertificates: []string{"cert-unassigned"},
				AllowedTeams:        []string{"system"},
				Admin:               false,
			},
		},
	}
	if err := initialConfig.Save(configPath); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	statePath := filepath.Join(tmpDir, "state.json")
	stateData := `{
		"certificates": [
			{
				"id": "cert-unassigned",
				"primary": "unassigned.com"
			}
		]
	}`
	if err := os.WriteFile(statePath, []byte(stateData), 0644); err != nil {
		t.Fatalf("Failed to write state: %v", err)
	}

	cfg := config.MustLoad()
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	if err := os.WriteFile(filepath.Join(tmpDir, "cert-unassigned.crt"), []byte("mock-cert"), 0644); err != nil {
		t.Fatalf("Failed to write mock cert file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "cert-unassigned.key"), []byte("mock-key"), 0644); err != nil {
		t.Fatalf("Failed to write mock key file: %v", err)
	}

	t.Run("Access Blocked", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates", nil)
		req.Header.Set("Authorization", "Bearer fetch-token-empty")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var certs []CertificateResponse
		if err := json.NewDecoder(res.Body).Decode(&certs); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if len(certs) != 0 {
			t.Errorf("Expected 0 certificates returned for empty allowed_teams, got %d", len(certs))
		}
	})

	t.Run("Access Allowed", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates", nil)
		req.Header.Set("Authorization", "Bearer fetch-token-system")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var certs []CertificateResponse
		if err := json.NewDecoder(res.Body).Decode(&certs); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if len(certs) != 1 {
			t.Fatalf("Expected exactly 1 certificate returned for system allowed_teams, got %d", len(certs))
		}
		if certs[0].ID != "cert-unassigned" {
			t.Errorf("Expected cert-unassigned, got %q", certs[0].ID)
		}
	})
}

func TestStaticResourceProtection_Certificates(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-static-protect-certs-*")
	defer cleanup()
	configPath := os.Getenv("CONFIG_PATH")

	hashedAdmin, _ := GenerateArgon2idHash("admin-token")

	initialConfig := &config.Config{
		APIKeys: []config.APIKeyConfig{
			{
				ID:    "admin-id",
				Token: hashedAdmin,
				Admin: true,
			},
		},
		Certificates: []config.CertConfig{
			{
				ID:      "static-cert",
				Primary: "static.com",
				TeamID:  "static-team",
			},
		},
	}
	if err := initialConfig.Save(configPath); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	cfg := config.MustLoad()
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	authHeader := "Bearer admin-token"

	t.Run("Blocked Edit", func(t *testing.T) {
		payload := config.CertConfig{
			Primary: "static-edited.com",
			TeamID:  "static-team",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config/certificates/static-cert", bytes.NewReader(body))
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request, got %d", res.StatusCode)
		}

		var resp map[string]string
		json.NewDecoder(res.Body).Decode(&resp)
		if !strings.Contains(resp["error"], "cannot modify or delete statically configured resources via the API") {
			t.Errorf("Expected specific error message, got: %q", resp["error"])
		}
	})
}

func TestAdmin_FetchCertificates(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-admin-fetch-*")
	defer cleanup()

	hashedRootAdmin, _ := GenerateArgon2idHash("root-admin-token")
	hashedScopedAdmin, _ := GenerateArgon2idHash("scoped-admin-token")

	initialConfig := &config.Config{
		APIKeys: []config.APIKeyConfig{
			{
				ID:           "root-admin-id",
				Token:        hashedRootAdmin,
				AllowedTeams: []string{}, // Root Admin
				Admin:        true,
			},
			{
				ID:           "scoped-admin-id",
				Token:        hashedScopedAdmin,
				AllowedTeams: []string{"team-id-1"}, // Scoped Admin
				Admin:        true,
			},
		},
		Certificates: []config.CertConfig{
			{
				ID:      "cert-team-1",
				Primary: "team1.com",
				TeamID:  "team-id-1",
			},
			{
				ID:      "cert-team-2",
				Primary: "team2.com",
				TeamID:  "team-id-2",
			},
		},
	}
	if err := initialConfig.Save(os.Getenv("CONFIG_PATH")); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	// Write mock cert files
	for _, cc := range initialConfig.Certificates {
		if err := os.WriteFile(filepath.Join(tmpDir, cc.ID+".crt"), []byte("cert-for-"+cc.Primary), 0644); err != nil {
			t.Fatalf("Failed to write mock cert file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, cc.ID+".key"), []byte("key-for-"+cc.Primary), 0644); err != nil {
			t.Fatalf("Failed to write mock key file: %v", err)
		}
	}

	cfg := config.MustLoad()
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	t.Run("Root Admin - Fetch All", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates", nil)
		req.Header.Set("Authorization", "Bearer root-admin-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var certs []CertificateResponse
		if err := json.NewDecoder(res.Body).Decode(&certs); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if len(certs) != 2 {
			t.Fatalf("Expected exactly 2 certificates, got %d", len(certs))
		}
	})

	t.Run("Scoped Admin - Fetch Scoped Only", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates", nil)
		req.Header.Set("Authorization", "Bearer scoped-admin-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var certs []CertificateResponse
		if err := json.NewDecoder(res.Body).Decode(&certs); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if len(certs) != 1 {
			t.Fatalf("Expected exactly 1 certificate, got %d", len(certs))
		}
	})
}

func TestCertificateStatusEndpoints(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-cert-status-tests-*")
	defer cleanup()

	hashedAdmin, err := GenerateArgon2idHash("admin-token")
	if err != nil {
		t.Fatalf("Failed to hash admin token: %v", err)
	}
	hashedUser, err := GenerateArgon2idHash("user-token")
	if err != nil {
		t.Fatalf("Failed to hash user token: %v", err)
	}

	initialConfig := &config.Config{
		APIKeys: []config.APIKeyConfig{
			{
				ID:    "key-admin",
				Token: hashedAdmin,
				Admin: true,
			},
			{
				ID:                  "key-user",
				Token:               hashedUser,
				AllowedCertificates: []string{"cert-ok", "cert-warning", "cert-missing-key", "cert-unissued", "cert-user-overlap"},
				AllowedTeams:        []string{"team-user"},
			},
		},
		Certificates: []config.CertConfig{
			{
				ID:      "cert-ok",
				Primary: "ok.example.com",
				Sans:    []string{"www.ok.example.com"},
				TeamID:  "team-user",
			},
			{
				ID:      "cert-warning",
				Primary: "warning.example.com",
				TeamID:  "team-user",
			},
			{
				ID:      "cert-missing-key",
				Primary: "missing-key.example.com",
				TeamID:  "team-user",
			},
			{
				ID:      "cert-unissued",
				Primary: "unissued.example.com",
				TeamID:  "team-user",
			},
			{
				ID:      "cert-user-overlap",
				Primary: "overlap.example.com",
				TeamID:  "team-user",
			},
			{
				ID:      "z-cert-other-overlap",
				Primary: "overlap.example.com",
				TeamID:  "team-other",
			},
			{
				ID:      "cert-other",
				Primary: "other.example.com",
				TeamID:  "team-other",
			},
		},
	}
	if err := initialConfig.Save(os.Getenv("CONFIG_PATH")); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	now := time.Now()
	createAPITestCertificate(t, tmpDir, "cert-ok", "ok.example.com", []string{"www.ok.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), true)
	createAPITestCertificate(t, tmpDir, "cert-warning", "warning.example.com", nil, now.Add(-time.Hour), now.Add(10*24*time.Hour), true)
	createAPITestCertificate(t, tmpDir, "cert-missing-key", "missing-key.example.com", nil, now.Add(-time.Hour), now.Add(90*24*time.Hour), false)
	createAPITestCertificate(t, tmpDir, "cert-user-overlap", "overlap.example.com", nil, now.Add(-time.Hour), now.Add(90*24*time.Hour), true)
	createAPITestCertificate(t, tmpDir, "z-cert-other-overlap", "overlap.example.com", nil, now.Add(-time.Hour), now.Add(90*24*time.Hour), true)
	createAPITestCertificate(t, tmpDir, "cert-other", "other.example.com", nil, now.Add(-time.Hour), now.Add(90*24*time.Hour), true)

	cfg := config.MustLoad()
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	t.Run("List status is scoped and does not include PEM material", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/status", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK, got %d", res.StatusCode)
		}

		var raw bytes.Buffer
		if _, err := raw.ReadFrom(res.Body); err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}
		body := raw.String()
		if strings.Contains(body, "BEGIN CERTIFICATE") || strings.Contains(body, "BEGIN EC PRIVATE KEY") {
			t.Fatalf("Status response leaked PEM material: %s", body)
		}

		var statuses []CertificateStatusResponse
		if err := json.Unmarshal([]byte(body), &statuses); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if len(statuses) != 5 {
			t.Fatalf("Expected 5 scoped certificate statuses, got %d", len(statuses))
		}

		byID := map[string]CertificateStatusResponse{}
		for _, status := range statuses {
			byID[status.ID] = status
		}
		if _, ok := byID["cert-other"]; ok {
			t.Fatal("Unscoped certificate status was returned")
		}
		if _, ok := byID["z-cert-other-overlap"]; ok {
			t.Fatal("Unscoped overlapping certificate status was returned")
		}
		if byID["cert-ok"].Status != "ok" || !byID["cert-ok"].Issued || byID["cert-ok"].DaysRemaining == nil {
			t.Errorf("Expected cert-ok to be issued and ok, got %+v", byID["cert-ok"])
		}
		if byID["cert-warning"].Status != "warning" {
			t.Errorf("Expected cert-warning to be warning, got %+v", byID["cert-warning"])
		}
		if byID["cert-missing-key"].Status != "critical" || byID["cert-missing-key"].Issued {
			t.Errorf("Expected cert-missing-key to be critical and unissued, got %+v", byID["cert-missing-key"])
		}
		if byID["cert-unissued"].Status != "critical" || byID["cert-unissued"].Reason == "" {
			t.Errorf("Expected cert-unissued to be critical with reason, got %+v", byID["cert-unissued"])
		}
		if byID["cert-user-overlap"].Status != "ok" || !byID["cert-user-overlap"].Issued {
			t.Errorf("Expected cert-user-overlap to be ok and issued, got %+v", byID["cert-user-overlap"])
		}
	})

	t.Run("Single status by identifier", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/ok.example.com/status", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK, got %d", res.StatusCode)
		}

		var status CertificateStatusResponse
		if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if status.ID != "cert-ok" || status.Status != "ok" || status.IssuerCommonName == "" {
			t.Errorf("Unexpected single status response: %+v", status)
		}
	})

	t.Run("Single status resolves domain within allowed scope even with overlapping newer certificate", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/overlap.example.com/status", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK, got %d", res.StatusCode)
		}

		var status CertificateStatusResponse
		if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if status.ID != "cert-user-overlap" {
			t.Errorf("Expected cert-user-overlap to be resolved, got %s", status.ID)
		}
	})

	t.Run("Admin can fetch metadata status", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/cert-ok/status", nil)
		req.Header.Set("Authorization", "Bearer admin-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK, got %d", res.StatusCode)
		}
	})

	t.Run("Single status respects scoping", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/cert-other/status", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("Expected 404 Not Found, got %d", res.StatusCode)
		}
	})
}

func TestRawCertificateEndpoints(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-raw-cert-tests-*")
	defer cleanup()

	hashedAdmin, err := GenerateArgon2idHash("admin-token")
	if err != nil {
		t.Fatalf("Failed to hash token: %v", err)
	}
	hashedUser, err := GenerateArgon2idHash("user-token")
	if err != nil {
		t.Fatalf("Failed to hash token: %v", err)
	}

	initialConfig := &config.Config{
		APIKeys: []config.APIKeyConfig{
			{
				ID:    "key-admin",
				Token: hashedAdmin,
				Admin: true,
			},
			{
				ID:                  "key-user",
				Token:               hashedUser,
				AllowedCertificates: []string{"cert-active", "cert-unissued", "a-cert-overlap"},
				AllowedTeams:        []string{"team-user"},
			},
		},
		Certificates: []config.CertConfig{
			{
				ID:      "cert-active",
				Primary: "active.com",
				Sans:    []string{"*.active.com", "extra.active.com"},
				TeamID:  "team-user",
			},
			{
				ID:      "cert-unissued",
				Primary: "unissued.com",
				TeamID:  "team-user",
			},
			{
				ID:      "a-cert-overlap",
				Primary: "overlap.com",
				TeamID:  "team-user",
			},
			{
				ID:      "z-cert-overlap",
				Primary: "overlap.com",
				TeamID:  "team-other",
			},
			{
				ID:      "cert-other",
				Primary: "other.com",
				TeamID:  "team-other",
			},
		},
	}
	if err := initialConfig.Save(os.Getenv("CONFIG_PATH")); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	err = os.WriteFile(filepath.Join(tmpDir, "cert-active.crt"), []byte("PEM-CERT-ACTIVE"), 0644)
	if err != nil {
		t.Fatalf("Write cert failed: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "cert-active.key"), []byte("PEM-KEY-ACTIVE"), 0644)
	if err != nil {
		t.Fatalf("Write key failed: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "a-cert-overlap.crt"), []byte("PEM-CERT-OVERLAP-USER"), 0644)
	if err != nil {
		t.Fatalf("Write cert failed: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "a-cert-overlap.key"), []byte("PEM-KEY-OVERLAP-USER"), 0644)
	if err != nil {
		t.Fatalf("Write key failed: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "z-cert-overlap.crt"), []byte("PEM-CERT-OVERLAP-OTHER"), 0644)
	if err != nil {
		t.Fatalf("Write cert failed: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "z-cert-overlap.key"), []byte("PEM-KEY-OVERLAP-OTHER"), 0644)
	if err != nil {
		t.Fatalf("Write key failed: %v", err)
	}

	cfg := config.MustLoad()
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	t.Run("Get certificate by ID - Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/cert-active/certificate", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}
		var body bytes.Buffer
		body.ReadFrom(res.Body)
		if body.String() != "PEM-CERT-ACTIVE" {
			t.Errorf("Expected PEM-CERT-ACTIVE, got %q", body.String())
		}
		if res.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("Expected text/plain, got %q", res.Header.Get("Content-Type"))
		}
	})

	t.Run("Get private key by ID - Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/cert-active/private-key", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}
		var body bytes.Buffer
		body.ReadFrom(res.Body)
		if body.String() != "PEM-KEY-ACTIVE" {
			t.Errorf("Expected PEM-KEY-ACTIVE, got %q", body.String())
		}
	})

	t.Run("Get certificate by primary domain - Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/active.com/certificate", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}
		var body bytes.Buffer
		body.ReadFrom(res.Body)
		if body.String() != "PEM-CERT-ACTIVE" {
			t.Errorf("Expected PEM-CERT-ACTIVE, got %q", body.String())
		}
	})

	t.Run("Get certificate by domain - Resolves allowed certificate when unallowed cert matches same domain with newer ID", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/overlap.com/certificate", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK, got %d", res.StatusCode)
		}
		var body bytes.Buffer
		body.ReadFrom(res.Body)
		if body.String() != "PEM-CERT-OVERLAP-USER" {
			t.Errorf("Expected PEM-CERT-OVERLAP-USER, got %q", body.String())
		}
	})

	t.Run("Get private key by domain - Resolves allowed certificate when unallowed cert matches same domain with newer ID", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/overlap.com/private-key", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK, got %d", res.StatusCode)
		}
		var body bytes.Buffer
		body.ReadFrom(res.Body)
		if body.String() != "PEM-KEY-OVERLAP-USER" {
			t.Errorf("Expected PEM-KEY-OVERLAP-USER, got %q", body.String())
		}
	})

	t.Run("Get certificate by SAN wildcard domain - Success", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/sub.active.com/certificate", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}
		var body bytes.Buffer
		body.ReadFrom(res.Body)
		if body.String() != "PEM-CERT-ACTIVE" {
			t.Errorf("Expected PEM-CERT-ACTIVE, got %q", body.String())
		}
	})

	t.Run("Get certificate by identifier - Scoping Inaccessible Not Found", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/cert-other/certificate", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 Not Found, got %d", res.StatusCode)
		}
	})

	t.Run("Get certificate by identifier - Not Yet Issued", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/cert-unissued/certificate", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 Not Found, got %d", res.StatusCode)
		}
	})

	t.Run("Get certificate by identifier - Config Not Found", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates/nonexistent.com/certificate", nil)
		req.Header.Set("Authorization", "Bearer user-token")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 Not Found, got %d", res.StatusCode)
		}
	})
}
