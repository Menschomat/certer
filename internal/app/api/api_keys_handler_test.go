package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"certer/internal/app/config"
)

func TestControlPlaneAPI_APIKeys(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "control-plane-api-key-tests-*")
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
	server := NewServer(tmpDir, cfg, nil)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	adminHeader := "Bearer " + testAdminToken

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
		if len(keys) != 1 {
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

func TestScopedAdmin_APIKeys(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-key-scoped-*")
	defer cleanup()
	configPath := os.Getenv("CONFIG_PATH")

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
				AllowedTeams: []string{},
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
