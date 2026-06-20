package api

import (
	"context"
	"net/http"
	"net/http/httptest"
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
			name:           "Admin token accessing certs - Allowed",
			token:          "admin-token",
			path:           "/api/v1/certificates",
			method:         "GET",
			expectedStatus: http.StatusOK,
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
