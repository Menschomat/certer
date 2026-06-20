package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cert-central/internal/app/config"
)

func TestTeamConfigAndScoping(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-team-scoping-tests-*")
	defer cleanup()
	configPath := os.Getenv("CONFIG_PATH")

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
				Token: testAdminHash,
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

	adminHeader := "Bearer " + testAdminToken

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

		if len(certs) != 1 {
			t.Fatalf("Expected exactly 1 certificate in scoped response, got %d: %+v", len(certs), certs)
		}
		if certs[0].ID != "cert-id-1" {
			t.Errorf("Expected cert-id-1 in response, got %q", certs[0].ID)
		}
	})
}

func TestStaticResourceProtection_Teams(t *testing.T) {
	tmpDir, cleanup := setupTestEnv(t, "api-static-protect-teams-*")
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
