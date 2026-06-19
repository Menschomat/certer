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
	"time"

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

	server := NewServer("", nil, apiKeys)

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

	server := NewServer("", nil, apiKeys)

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


