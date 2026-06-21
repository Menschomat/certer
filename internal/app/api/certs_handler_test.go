package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"certer/internal/app/config"
)

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

	cfg := config.Load()
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
		loadedCfg := config.Load()
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

		loadedCfg := config.Load()
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

	cfg := config.Load()
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

	cfg := config.Load()
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

	cfg := config.Load()
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

	cfg := config.Load()
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
		if certs[0].ID != "cert-team-1" {
			t.Errorf("Expected cert-team-1, got %q", certs[0].ID)
		}
	})
}

