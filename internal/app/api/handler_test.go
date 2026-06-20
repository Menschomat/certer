package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cert-central/internal/app/config"
)

func TestHandleHealth(t *testing.T) {
	server := NewServer("", &config.Config{}, nil)
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
	server := NewServer("", &config.Config{}, nil)
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

	hashedToken, err := GenerateArgon2idHash("blabliblub")
	if err != nil {
		t.Fatalf("Failed to generate test token hash: %v", err)
	}

	apiKeys := []config.APIKeyConfig{
		{
			ID:             "019035a1-7b00-7521-8280-60b6adbf47ee",
			Token:          hashedToken,
			AllowedDomains: []string{"menscho.space", "weihrauchphoto.de"},
			AllowedTeams:   []string{"system"},
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

func TestAuthentication_Roles(t *testing.T) {
	hashedFetchToken, err := GenerateArgon2idHash("fetch-token")
	if err != nil {
		t.Fatalf("Failed to generate fetch token hash: %v", err)
	}
	hashedAdminToken, err := GenerateArgon2idHash("admin-token")
	if err != nil {
		t.Fatalf("Failed to generate admin token hash: %v", err)
	}

	apiKeys := []config.APIKeyConfig{
		{
			Token:          hashedFetchToken,
			AllowedDomains: []string{"example.com"},
			Admin:          false,
		},
		{
			Token:          hashedAdminToken,
			Admin:          true,
		},
	}

	cfg := &config.Config{
		APIKeys: apiKeys,
	}
	server := NewServer("", cfg, nil)

	// We wrap a dummy handler with s.Authenticate to test path-based authorization.
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	authHandler := server.Authenticate(dummyHandler)

	tests := []struct {
		name           string
		token          string
		path           string
		method         string
		expectedStatus int
	}{
		{
			name:           "Fetch token accessing certs - Allowed",
			token:          "fetch-token",
			path:           "/api/v1/certificates",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Fetch token accessing config - Forbidden",
			token:          "fetch-token",
			path:           "/api/v1/config/certificates",
			method:         "GET",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Admin token accessing config - Allowed",
			token:          "admin-token",
			path:           "/api/v1/config/certificates",
			method:         "GET",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Admin token accessing certs - Forbidden",
			token:          "admin-token",
			path:           "/api/v1/certificates",
			method:         "GET",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "No token accessing config - Unauthorized",
			token:          "",
			path:           "/api/v1/config/certificates",
			method:         "GET",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid token accessing config - Unauthorized",
			token:          "invalid-token",
			path:           "/api/v1/config/certificates",
			method:         "GET",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rr := httptest.NewRecorder()
			authHandler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestServer_ReloadConfig_Concurrency(t *testing.T) {
	hashedFetchToken1, _ := GenerateArgon2idHash("fetch-token-1")
	hashedFetchToken2, _ := GenerateArgon2idHash("fetch-token-2")

	apiKeys := []config.APIKeyConfig{
		{
			Token:          hashedFetchToken1,
			AllowedDomains: []string{"domain1.com"},
		},
	}

	cfg := &config.Config{
		APIKeys: apiKeys,
	}
	server := NewServer("", cfg, nil)

	// Spin up goroutines making requests to simulate traffic
	stopChan := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				req := httptest.NewRequest("GET", "/api/v1/certificates", nil)
				req.Header.Set("Authorization", "Bearer fetch-token-1")
				rr := httptest.NewRecorder()
				server.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				})).ServeHTTP(rr, req)
			}
		}
	}()

	// Perform concurrent reloads
	for i := 0; i < 50; i++ {
		newKeys := []config.APIKeyConfig{
			{
				Token:          hashedFetchToken2,
				AllowedDomains: []string{"domain2.com"},
			},
		}
		server.ReloadConfig(nil, newKeys)
		time.Sleep(1 * time.Millisecond)
	}

	close(stopChan)
}

type MockReloader struct {
	CalledCount int
	CalledCerts []config.CertConfig
}

func (m *MockReloader) ReloadConfig(ctx context.Context, certificates []config.CertConfig) {
	m.CalledCount++
	m.CalledCerts = certificates
}

func TestControlPlaneAPI(t *testing.T) {
	// Create temporary directory for configuration persistence testing
	tmpDir, err := os.MkdirTemp("", "control-plane-api-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	configPath := filepath.Join(tmpDir, "config.json")
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

	// Set up initial configuration structure
	initialConfig := &config.Config{
		Port: "8080",
		APIKeys: []config.APIKeyConfig{
			{
				ID:    "admin-key-id",
				Token: "$argon2id$v=19$m=65536,t=3,p=2$5e3EMry5f9M8wHWfOI3uOA$EoHEmZt426KKoow/3j7a4o0Yo/oKdZwGpNy+FTowmTs", // hash for "blabliblub"
				Admin: true,
			},
			{
				ID:             "fetch-key-id",
				Token:          "fetch-token-hash",
				AllowedDomains: []string{"example.com"},
				Admin:          false,
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

	// Admin Authorization Header
	adminHeader := "Bearer blabliblub"

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

		// Verify reloader was called
		if reloader.CalledCount != 1 {
			t.Errorf("Expected reloader to be called once, got %d", reloader.CalledCount)
		}

		// Verify saved config file has the new certificate
		loadedCfg := config.Load()
		allCerts := loadedCfg.AllCertificates()
		if len(allCerts) != 2 || allCerts[1].Primary != "newdomain.com" || allCerts[1].ID != newCertID {
			t.Errorf("Expected new certificate to be saved on disk, got: %+v", allCerts)
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
				if len(c.Sans) != 2 || c.Sans[0] != "admin.example.com" || c.Description != "Updated Description" {
					t.Errorf("Expected updated SANs and description, got %+v", c)
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

	t.Run("GET API Keys Configuration", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/config/api_keys", nil)
		req.Header.Set("Authorization", adminHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var keys []config.APIKeyConfig
		if err := json.NewDecoder(res.Body).Decode(&keys); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("Unexpected API keys count: %d", len(keys))
		}
	})

	var newKeyID string
	t.Run("POST API Key Configuration - Success", func(t *testing.T) {
		newKey := config.APIKeyConfig{
			Description:    "New Deploy Key",
			AllowedDomains: []string{"newdomain.com"},
			AllowedTeams:   []string{"team-id-1"},
			Admin:          false,
		}
		body, _ := json.Marshal(newKey)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/api_keys", bytes.NewReader(body))
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

		type apiResponse struct {
			ID             string   `json:"id"`
			Token          string   `json:"token"`
			CleartextToken string   `json:"cleartext_token"`
			Description    string   `json:"description"`
			AllowedDomains []string `json:"allowed_domains"`
			AllowedTeams   []string `json:"allowed_teams"`
			Admin          bool     `json:"admin"`
		}
		var resp apiResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		newKeyID = resp.ID
		if newKeyID == "" {
			t.Errorf("Expected generated UUID in response")
		}
		if len(resp.CleartextToken) != 64 {
			t.Errorf("Expected 64-character cleartext token, got %s (length %d)", resp.CleartextToken, len(resp.CleartextToken))
		}

		loadedCfg := config.Load()
		found := false
		for _, k := range loadedCfg.AllAPIKeys() {
			if k.ID == newKeyID {
				found = true
				if k.Description != "New Deploy Key" {
					t.Errorf("Expected description 'New Deploy Key', got %s", k.Description)
				}
				if len(k.AllowedTeams) != 1 || k.AllowedTeams[0] != "team-id-1" {
					t.Errorf("Expected allowed_teams to contain 'team-id-1', got %+v", k.AllowedTeams)
				}
			}
		}
		if !found {
			t.Errorf("Expected new API Key configuration to be saved, got: %+v", loadedCfg.AllAPIKeys())
		}
	})

	t.Run("PUT API Key Configuration - Success", func(t *testing.T) {
		updatedKey := config.APIKeyConfig{
			Description:    "Updated Deploy Key",
			AllowedDomains: []string{"updated-domain.com"},
			AllowedTeams:   []string{"team-id-1"},
			Admin:          true,
		}
		body, _ := json.Marshal(updatedKey)
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config/api_keys/"+newKeyID, bytes.NewReader(body))
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
		for _, k := range loadedCfg.AllAPIKeys() {
			if k.ID == newKeyID {
				if !k.Admin || len(k.AllowedDomains) != 1 || k.AllowedDomains[0] != "updated-domain.com" || k.Description != "Updated Deploy Key" || len(k.AllowedTeams) != 1 || k.AllowedTeams[0] != "team-id-1" {
					t.Errorf("Expected updated key settings, got: %+v", k)
				}
			}
		}
	})

	t.Run("DELETE API Key Configuration - Success", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/api_keys/"+newKeyID, nil)
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

func TestTeamConfigAndScoping(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "api-team-scoping-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

	hashedToken, err := GenerateArgon2idHash("deploy-token")
	if err != nil {
		t.Fatalf("Failed to generate token hash: %v", err)
	}

	initialConfig := &config.Config{
		Port: "8080",
		APIKeys: []config.APIKeyConfig{
			{
				ID:             "key-id-1",
				Token:          hashedToken,
				AllowedDomains: []string{"bly.li"},
				AllowedTeams:   []string{"team-id-1"},
				Admin:          false,
			},
			{
				ID:    "admin-key-id",
				Token: "$argon2id$v=19$m=65536,t=3,p=2$5e3EMry5f9M8wHWfOI3uOA$EoHEmZt426KKoow/3j7a4o0Yo/oKdZwGpNy+FTowmTs", // hash for "blabliblub"
				Admin: true,
			},
		},
		Certificates: []config.CertConfig{
			{
				ID:      "cert-id-1",
				Primary: "bly.li",
				Sans:    []string{"dev.bly.li"},
				TeamID:  "team-id-1",
			},
			{
				ID:      "cert-id-2",
				Primary: "bly.li",
				Sans:    []string{"prod.bly.li"},
				TeamID:  "team-id-2",
			},
		},
		Teams: []config.TeamConfig{
			{
				ID:          "team-id-1",
				Name:        "Team 1",
				Description: "First test team",
			},
			{
				ID:          "team-id-2",
				Name:        "Team 2",
				Description: "Second test team",
			},
		},
	}
	if err := initialConfig.Save(configPath); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	for _, cc := range initialConfig.Certificates {
		err := os.WriteFile(filepath.Join(tmpDir, cc.ID+".crt"), []byte("cert-for-"+cc.Primary), 0644)
		if err != nil {
			t.Fatalf("Failed to write mock cert file: %v", err)
		}
		err = os.WriteFile(filepath.Join(tmpDir, cc.ID+".key"), []byte("key-for-"+cc.Primary), 0644)
		if err != nil {
			t.Fatalf("Failed to write mock key file: %v", err)
		}
	}

	cfg := config.Load()
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	adminHeader := "Bearer blabliblub"

	t.Run("GET Teams Config (Admin)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/config/teams", nil)
		req.Header.Set("Authorization", adminHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var teams []config.TeamConfig
		if err := json.NewDecoder(res.Body).Decode(&teams); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if len(teams) != 3 {
			t.Errorf("Expected 3 teams (including built-in system team), got %d", len(teams))
		}
	})

	var createdTeamID string
	t.Run("POST Create Team Config (Admin)", func(t *testing.T) {
		newTeam := config.TeamConfig{
			Name:        "Team 3",
			Description: "Third test team",
		}
		body, _ := json.Marshal(newTeam)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/teams", bytes.NewReader(body))
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

		var created config.TeamConfig
		if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		createdTeamID = created.ID
		if createdTeamID == "" {
			t.Errorf("Expected generated UUID in response")
		}

		loadedCfg := config.Load()
		if len(loadedCfg.AllTeams()) != 4 {
			t.Errorf("Expected 4 teams total (including system), got %d: %+v", len(loadedCfg.AllTeams()), loadedCfg.AllTeams())
		}
	})

	t.Run("PUT Update Team Config (Admin)", func(t *testing.T) {
		updatedTeam := config.TeamConfig{
			Name:        "Team 3 Updated",
			Description: "Updated Description",
		}
		body, _ := json.Marshal(updatedTeam)
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config/teams/"+createdTeamID, bytes.NewReader(body))
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
		found := false
		for _, tVal := range loadedCfg.AllTeams() {
			if tVal.ID == createdTeamID {
				found = true
				if tVal.Name != "Team 3 Updated" || tVal.Description != "Updated Description" {
					t.Errorf("Expected updated fields, got %+v", tVal)
				}
			}
		}
		if !found {
			t.Errorf("Expected to find updated team %q", createdTeamID)
		}
	})

	t.Run("DELETE Team Config - Fail if in use by certificates", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/teams/team-id-2", nil)
		req.Header.Set("Authorization", adminHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request, got %d", res.StatusCode)
		}
	})

	t.Run("DELETE Team Config - Fail if in use by API keys", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/teams/team-id-1", nil)
		req.Header.Set("Authorization", adminHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request, got %d", res.StatusCode)
		}
	})

	t.Run("DELETE Team Config (Admin)", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/teams/"+createdTeamID, nil)
		req.Header.Set("Authorization", adminHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusNoContent {
			t.Errorf("Expected 204 No Content, got %d", res.StatusCode)
		}

		loadedCfg := config.Load()
		if len(loadedCfg.AllTeams()) != 3 {
			t.Errorf("Expected 3 teams (including system) saved on disk after delete, got %d", len(loadedCfg.AllTeams()))
		}
	})

	t.Run("GET Scoped Certificates (Fetch Token scoping check)", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certificates", nil)
		req.Header.Set("Authorization", "Bearer deploy-token")
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

		// Only cert-id-1 should be returned (belongs to team-id-1).
		// cert-id-2 (team-id-2) must be filtered out!
		if len(certs) != 1 {
			t.Fatalf("Expected exactly 1 certificate in scoped response, got %d: %+v", len(certs), certs)
		}
		if certs[0].ID != "cert-id-1" {
			t.Errorf("Expected cert-id-1 in response, got %q", certs[0].ID)
		}
	})
}

func TestScopedAdmin_Certificates(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "api-cert-scoped-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

	hashedScopedAdmin, _ := GenerateArgon2idHash("scoped-admin-token")

	// Pre-configure some teams and certs. We make them static so they are parsed, but since we are modifying state,
	// we will also check behavior against dynamic certs/keys.
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

	// Create a state.json with certificates for team-1 and team-2
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

	// Assertion 1: GET /api/v1/config/certificates returns ONLY certificates belonging to "team-id-1"
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

	// Assertion 2: POST /api/v1/config/certificates with team_id: "team-id-2" returns 403 Forbidden
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

	// Assertion 3: POST with team_id: "team-id-1" returns 201 Created
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

	// Assertion 4: DELETE /api/v1/config/certificates/cert-team-2 returns 404 Not Found (Stealthy Deny)
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

	// Assertion 5: PUT /api/v1/config/certificates/cert-team-1 trying to update team_id to "team-id-2" returns 403 Forbidden
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
	tmpDir, err := os.MkdirTemp("", "api-cert-deny-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

	hashedFetchTokenEmpty, _ := GenerateArgon2idHash("fetch-token-empty")
	hashedFetchTokenSystem, _ := GenerateArgon2idHash("fetch-token-system")

	// Certificate without a team_id (which should default to "system")
	initialConfig := &config.Config{
		APIKeys: []config.APIKeyConfig{
			{
				ID:             "fetch-key-empty",
				Token:          hashedFetchTokenEmpty,
				AllowedDomains: []string{"unassigned.com"},
				AllowedTeams:   []string{}, // empty
				Admin:          false,
			},
			{
				ID:             "fetch-key-system",
				Token:          hashedFetchTokenSystem,
				AllowedDomains: []string{"unassigned.com"},
				AllowedTeams:   []string{"system"},
				Admin:          false,
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

	// Write mock cert/key files so the handler considers them "issued"
	err = os.WriteFile(filepath.Join(tmpDir, "cert-unassigned.crt"), []byte("mock-cert"), 0644)
	if err != nil {
		t.Fatalf("Failed to write mock cert file: %v", err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "cert-unassigned.key"), []byte("mock-key"), 0644)
	if err != nil {
		t.Fatalf("Failed to write mock key file: %v", err)
	}

	// Token Setup 1: fetch token with empty allowed_teams
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

	// Token Setup 2: fetch token with allowed_teams ["system"]
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

func TestScopedAdmin_APIKeys(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "api-key-scoped-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

	hashedScopedAdmin, _ := GenerateArgon2idHash("scoped-admin-token")
	hashedRootAdmin, _ := GenerateArgon2idHash("root-admin-token")

	initialConfig := &config.Config{
		APIKeys: []config.APIKeyConfig{
			{
				ID:           "scoped-admin-id",
				Token:        hashedScopedAdmin,
				AllowedTeams: []string{"team-id-1"},
				Admin:        true,
			},
			{
				ID:           "root-admin-id",
				Token:        hashedRootAdmin,
				AllowedTeams: []string{}, // Root Admin
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
		"api_keys": [
			{
				"id": "key-team-1",
				"token": "$argon2id$v=19$m=65536,t=3,p=2$5e3EMry5f9M8wHWfOI3uOA$EoHEmZt426KKoow/3j7a4o0Yo/oKdZwGpNy+FTowmTs",
				"allowed_teams": ["team-id-1"]
			},
			{
				"id": "key-team-2",
				"token": "$argon2id$v=19$m=65536,t=3,p=2$5e3EMry5f9M8wHWfOI3uOA$EoHEmZt426KKoow/3j7a4o0Yo/oKdZwGpNy+FTowmTs",
				"allowed_teams": ["team-id-2"]
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

	// Assertion 1: GET /api/v1/config/api_keys returns only keys scoped to a subset of ["team-id-1"]
	t.Run("List Visibility", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/config/api_keys", nil)
		req.Header.Set("Authorization", authHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 OK, got %d", res.StatusCode)
		}

		var keys []config.APIKeyConfig
		if err := json.NewDecoder(res.Body).Decode(&keys); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		// It should see itself (scoped-admin-id) and key-team-1.
		// It should NOT see root-admin-id or key-team-2.
		if len(keys) != 2 {
			t.Fatalf("Expected exactly 2 API keys, got %d: %+v", len(keys), keys)
		}
		ids := make(map[string]bool)
		for _, k := range keys {
			ids[k.ID] = true
		}
		if !ids["scoped-admin-id"] || !ids["key-team-1"] {
			t.Errorf("Expected scoped-admin-id and key-team-1, got: %+v", ids)
		}
	})

	// Assertion 2: POST /api/v1/config/api_keys with allowed_teams: ["team-id-1", "team-id-2"] returns 403 Forbidden
	t.Run("Cross-Team Escalation block", func(t *testing.T) {
		payload := config.APIKeyConfig{
			AllowedTeams: []string{"team-id-1", "team-id-2"},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/api_keys", bytes.NewReader(body))
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

	// Assertion 3: POST with admin: true and allowed_teams: [] (Root Admin payload) returns 403 Forbidden
	t.Run("Root Admin Escalation block", func(t *testing.T) {
		payload := config.APIKeyConfig{
			Admin:        true,
			AllowedTeams: []string{},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/api_keys", bytes.NewReader(body))
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

	// Assertion 4: POST with allowed_teams: ["team-id-1"] returns 201 Created
	t.Run("Authorized Key Creation", func(t *testing.T) {
		payload := config.APIKeyConfig{
			AllowedTeams: []string{"team-id-1"},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/config/api_keys", bytes.NewReader(body))
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

	// Assertion 5: DELETE targeting a key scoped to another team returns 404 Not Found (Stealthy Deny)
	t.Run("Unauthorized Key deletion", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/api_keys/key-team-2", nil)
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
}

func TestStaticResourceProtection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "api-static-protect-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

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
		Teams: []config.TeamConfig{
			{
				ID:   "static-team",
				Name: "Static Team",
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

	// Assertion 1: PUT /api/v1/config/certificates/static-cert returns 400 Bad Request
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

	// Assertion 2: DELETE /api/v1/config/teams/static-team returns 400 Bad Request
	t.Run("Blocked Delete", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/teams/static-team", nil)
		req.Header.Set("Authorization", authHeader)
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

	// Assertion 3: DELETE /api/v1/config/teams/system returns 400 Bad Request (Built-in team protection)
	t.Run("Built-in Team Protection", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/config/teams/system", nil)
		req.Header.Set("Authorization", authHeader)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer res.Body.Close()

		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("Expected 400 Bad Request, got %d", res.StatusCode)
		}
	})
}




