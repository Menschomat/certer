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
			},
		},
	}
	if err := initialConfig.Save(configPath); err != nil {
		t.Fatalf("Failed to save initial config: %v", err)
	}

	reloader := &MockReloader{}
	server := NewServer(tmpDir, initialConfig, reloader)
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
		if len(loadedCfg.Certificates) != 2 || loadedCfg.Certificates[1].Primary != "newdomain.com" || loadedCfg.Certificates[1].ID != newCertID {
			t.Errorf("Expected new certificate to be saved on disk, got: %+v", loadedCfg.Certificates)
		}
	})

	t.Run("POST Certificate Configuration - Duplicate Allowed", func(t *testing.T) {
		duplicateCert := config.CertConfig{
			Primary: "example.com",
			Sans:    []string{"another.example.com"},
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
			Primary:     "example.com",
			Sans:        []string{"admin.example.com", "mail.example.com"},
			Description: "Updated Description",
		}
		body, _ := json.Marshal(updatedCert)
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config/certificates/example-cert-id", bytes.NewReader(body))
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
		for _, c := range loadedCfg.Certificates {
			if c.ID == "example-cert-id" {
				if len(c.Sans) != 2 || c.Sans[0] != "admin.example.com" || c.Description != "Updated Description" {
					t.Errorf("Expected updated SANs and description, got %+v", c)
				}
			}
		}
	})

	t.Run("PUT Certificate Configuration - Not Found", func(t *testing.T) {
		updatedCert := config.CertConfig{
			Sans: []string{"mail.nonexistent.com"},
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
		for _, k := range loadedCfg.APIKeys {
			if k.ID == newKeyID {
				found = true
				if k.Description != "New Deploy Key" {
					t.Errorf("Expected description 'New Deploy Key', got %s", k.Description)
				}
			}
		}
		if !found {
			t.Errorf("Expected new API Key configuration to be saved, got: %+v", loadedCfg.APIKeys)
		}
	})

	t.Run("PUT API Key Configuration - Success", func(t *testing.T) {
		updatedKey := config.APIKeyConfig{
			Description:    "Updated Deploy Key",
			AllowedDomains: []string{"updated-domain.com"},
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
		for _, k := range loadedCfg.APIKeys {
			if k.ID == newKeyID {
				if !k.Admin || len(k.AllowedDomains) != 1 || k.AllowedDomains[0] != "updated-domain.com" || k.Description != "Updated Deploy Key" {
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



