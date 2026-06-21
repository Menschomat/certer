package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// createTempConfig creates a temporary config.json with the given content
// and registers automated directory cleanup using t.Cleanup.
func createTempConfig(t *testing.T, content string) string {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "config-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write config.json: %v", err)
	}
	return configPath
}

func TestLoadConfig(t *testing.T) {
	configJSON := `{
		"port": "9090",
		"env": "production",
		"acme_email": "admin@example.com",
		"acme_directory_url": "https://localhost:14000/dir",
		"dns_provider": "hetzner",
		"renew_threshold_days": 15,
		"check_interval_hours": 12,
		"certificates": [
			{
				"id": "019035a1-7b00-7521-8280-60b6adbf47eb",
				"primary": "example.com",
				"sans": ["*.example.com", "www.example.com"],
				"team_id": "019035a1-7b00-7521-8280-60b6adbf47ed"
			}
		],
		"api_keys": [
			{
				"id": "019035a1-7b00-7521-8280-60b6adbf47ec",
				"token": "blabliblub",
				"allowed_domains": ["menscho.space", "weihrauchphoto.de"],
				"allowed_teams": ["019035a1-7b00-7521-8280-60b6adbf47ed"]
			}
		],
		"teams": [
			{
				"id": "019035a1-7b00-7521-8280-60b6adbf47ed",
				"name": "Dev Team",
				"description": "Development environment"
			}
		]
	}`

	configPath := createTempConfig(t, configJSON)
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

	cfg := Load()

	if cfg.Port != "9090" {
		t.Errorf("Expected Port '9090', got %q", cfg.Port)
	}
	if cfg.Env != "production" {
		t.Errorf("Expected Env 'production', got %q", cfg.Env)
	}
	if cfg.ACMEEmail != "admin@example.com" {
		t.Errorf("Expected ACMEEmail 'admin@example.com', got %q", cfg.ACMEEmail)
	}
	if cfg.ACMEDirectoryURL != "https://localhost:14000/dir" {
		t.Errorf("Expected ACMEDirectoryURL, got %q", cfg.ACMEDirectoryURL)
	}
	if cfg.DNSProvider != "hetzner" {
		t.Errorf("Expected DNSProvider 'hetzner', got %q", cfg.DNSProvider)
	}
	if cfg.RenewThresholdDays != 15 {
		t.Errorf("Expected RenewThresholdDays 15, got %d", cfg.RenewThresholdDays)
	}
	if cfg.CheckIntervalHours != 12 {
		t.Errorf("Expected CheckIntervalHours 12, got %d", cfg.CheckIntervalHours)
	}

	expectedCerts := []CertConfig{
		{
			ID:      "019035a1-7b00-7521-8280-60b6adbf47eb",
			Primary: "example.com",
			Sans:    []string{"*.example.com", "www.example.com"},
			TeamID:  "019035a1-7b00-7521-8280-60b6adbf47ed",
		},
	}
	if !reflect.DeepEqual(cfg.Certificates, expectedCerts) {
		t.Errorf("Expected Certificates %+v, got %+v", expectedCerts, cfg.Certificates)
	}

	expectedAPIKeys := []APIKeyConfig{
		{
			ID:             "019035a1-7b00-7521-8280-60b6adbf47ec",
			Token:          "blabliblub",
			AllowedDomains: []string{"menscho.space", "weihrauchphoto.de"},
			AllowedTeams:   []string{"019035a1-7b00-7521-8280-60b6adbf47ed"},
		},
	}
	if !reflect.DeepEqual(cfg.APIKeys, expectedAPIKeys) {
		t.Errorf("Expected APIKeys %+v, got %+v", expectedAPIKeys, cfg.APIKeys)
	}

	expectedTeams := []TeamConfig{
		{
			ID:          "019035a1-7b00-7521-8280-60b6adbf47ed",
			Name:        "Dev Team",
			Description: "Development environment",
		},
	}
	if !reflect.DeepEqual(cfg.Teams, expectedTeams) {
		t.Errorf("Expected Teams %+v, got %+v", expectedTeams, cfg.Teams)
	}
}

func TestLoadConfigEnvDynamicACME(t *testing.T) {
	// Subtest 1: Default environment (development) and no ACME URL set
	t.Run("default_development_no_acme_url", func(t *testing.T) {
		os.Unsetenv("ENV")
		os.Unsetenv("ACME_DIRECTORY_URL")
		os.Setenv("CONFIG_PATH", "/nonexistent_config_path_trigger_env_fallback.json")
		defer os.Unsetenv("CONFIG_PATH")

		cfg := Load()
		if cfg.Env != "development" {
			t.Errorf("expected default env development, got %q", cfg.Env)
		}
		expectedURL := "https://acme-staging-v02.api.letsencrypt.org/directory"
		if cfg.ACMEDirectoryURL != expectedURL {
			t.Errorf("expected staging ACME URL %q, got %q", expectedURL, cfg.ACMEDirectoryURL)
		}
	})

	// Subtest 2: Production environment set via env var, no ACME URL set
	t.Run("production_env_var_no_acme_url", func(t *testing.T) {
		os.Setenv("ENV", "production")
		os.Unsetenv("ACME_DIRECTORY_URL")
		os.Setenv("CONFIG_PATH", "/nonexistent_config_path_trigger_env_fallback.json")
		defer os.Unsetenv("ENV")
		defer os.Unsetenv("CONFIG_PATH")

		cfg := Load()
		if cfg.Env != "production" {
			t.Errorf("expected env production, got %q", cfg.Env)
		}
		expectedURL := "https://acme-v02.api.letsencrypt.org/directory"
		if cfg.ACMEDirectoryURL != expectedURL {
			t.Errorf("expected production ACME URL %q, got %q", expectedURL, cfg.ACMEDirectoryURL)
		}
	})

	// Subtest 3: Production env set but ACME URL explicitly set
	t.Run("production_env_var_with_explicit_acme_url", func(t *testing.T) {
		os.Setenv("ENV", "production")
		os.Setenv("ACME_DIRECTORY_URL", "https://localhost:14000/dir")
		os.Setenv("CONFIG_PATH", "/nonexistent_config_path_trigger_env_fallback.json")
		defer os.Unsetenv("ENV")
		defer os.Unsetenv("ACME_DIRECTORY_URL")
		defer os.Unsetenv("CONFIG_PATH")

		cfg := Load()
		if cfg.Env != "production" {
			t.Errorf("expected env production, got %q", cfg.Env)
		}
		expectedURL := "https://localhost:14000/dir"
		if cfg.ACMEDirectoryURL != expectedURL {
			t.Errorf("expected custom ACME URL %q, got %q", expectedURL, cfg.ACMEDirectoryURL)
		}
	})

	// Subtest 4: JSON config with env production, no acme_directory_url
	t.Run("json_env_production_no_acme_url", func(t *testing.T) {
		configJSON := `{"env": "production"}`
		configPath := createTempConfig(t, configJSON)

		os.Setenv("CONFIG_PATH", configPath)
		defer os.Unsetenv("CONFIG_PATH")

		cfg := Load()
		if cfg.Env != "production" {
			t.Errorf("expected env production, got %q", cfg.Env)
		}
		expectedURL := "https://acme-v02.api.letsencrypt.org/directory"
		if cfg.ACMEDirectoryURL != expectedURL {
			t.Errorf("expected production ACME URL %q, got %q", expectedURL, cfg.ACMEDirectoryURL)
		}
	})
}

func TestLoadConfigZeroSSL(t *testing.T) {
	// Subtest 1: ZeroSSL provider via env var, no ACME URL set
	t.Run("zerossl_env_var_no_acme_url", func(t *testing.T) {
		os.Setenv("ACME_PROVIDER", "zerossl")
		os.Unsetenv("ACME_DIRECTORY_URL")
		os.Setenv("EAB_KID", "my_kid")
		os.Setenv("EAB_HMAC", "my_hmac")
		os.Setenv("CONFIG_PATH", "/nonexistent_config_path_trigger_env_fallback.json")
		defer os.Unsetenv("ACME_PROVIDER")
		defer os.Unsetenv("EAB_KID")
		defer os.Unsetenv("EAB_HMAC")
		defer os.Unsetenv("CONFIG_PATH")

		cfg := Load()
		if cfg.ACMEProvider != "zerossl" {
			t.Errorf("expected provider 'zerossl', got %q", cfg.ACMEProvider)
		}
		expectedURL := "https://acme.zerossl.com/v2/DV90"
		if cfg.ACMEDirectoryURL != expectedURL {
			t.Errorf("expected ZeroSSL ACME URL %q, got %q", expectedURL, cfg.ACMEDirectoryURL)
		}
		if cfg.EABKid != "my_kid" {
			t.Errorf("expected EABKid 'my_kid', got %q", cfg.EABKid)
		}
		if cfg.EABHmac != "my_hmac" {
			t.Errorf("expected EABHmac 'my_hmac', got %q", cfg.EABHmac)
		}
	})

	// Subtest 2: JSON config with provider zerossl
	t.Run("json_provider_zerossl", func(t *testing.T) {
		configJSON := `{
			"acme_provider": "zerossl",
			"eab_kid": "json_kid",
			"eab_hmac": "json_hmac"
		}`
		configPath := createTempConfig(t, configJSON)

		os.Setenv("CONFIG_PATH", configPath)
		defer os.Unsetenv("CONFIG_PATH")

		cfg := Load()
		if cfg.ACMEProvider != "zerossl" {
			t.Errorf("expected provider 'zerossl', got %q", cfg.ACMEProvider)
		}
		expectedURL := "https://acme.zerossl.com/v2/DV90"
		if cfg.ACMEDirectoryURL != expectedURL {
			t.Errorf("expected ZeroSSL ACME URL %q, got %q", expectedURL, cfg.ACMEDirectoryURL)
		}
		if cfg.EABKid != "json_kid" {
			t.Errorf("expected EABKid 'json_kid', got %q", cfg.EABKid)
		}
		if cfg.EABHmac != "json_hmac" {
			t.Errorf("expected EABHmac 'json_hmac', got %q", cfg.EABHmac)
		}
	})
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	configJSON := `{
		"port": "9090",
		"env": "development",
		"acme_email": "json@example.com"
	}`
	configPath := createTempConfig(t, configJSON)

	os.Setenv("CONFIG_PATH", configPath)
	os.Setenv("PORT", "9999")
	os.Setenv("ENV", "production")
	os.Setenv("ACME_EMAIL", "env@example.com")
	os.Setenv("ACME_PROVIDER", "zerossl")
	os.Setenv("EAB_KID", "env_kid")
	os.Setenv("EAB_HMAC", "env_hmac")
	os.Setenv("DNS_PROVIDER", "cloudflare")

	defer func() {
		os.Unsetenv("CONFIG_PATH")
		os.Unsetenv("PORT")
		os.Unsetenv("ENV")
		os.Unsetenv("ACME_EMAIL")
		os.Unsetenv("ACME_PROVIDER")
		os.Unsetenv("EAB_KID")
		os.Unsetenv("EAB_HMAC")
		os.Unsetenv("DNS_PROVIDER")
	}()

	cfg := Load()

	if cfg.Port != "9999" {
		t.Errorf("Expected Port '9999' from env override, got %q", cfg.Port)
	}
	if cfg.Env != "production" {
		t.Errorf("Expected Env 'production' from env override, got %q", cfg.Env)
	}
	if cfg.ACMEEmail != "env@example.com" {
		t.Errorf("Expected ACMEEmail 'env@example.com' from env override, got %q", cfg.ACMEEmail)
	}
	if cfg.ACMEProvider != "zerossl" {
		t.Errorf("Expected ACMEProvider 'zerossl' from env override, got %q", cfg.ACMEProvider)
	}
	if cfg.EABKid != "env_kid" {
		t.Errorf("Expected EABKid 'env_kid' from env override, got %q", cfg.EABKid)
	}
	if cfg.EABHmac != "env_hmac" {
		t.Errorf("Expected EABHmac 'env_hmac' from env override, got %q", cfg.EABHmac)
	}
	if cfg.DNSProvider != "cloudflare" {
		t.Errorf("Expected DNSProvider 'cloudflare' from env override, got %q", cfg.DNSProvider)
	}
}

func TestLoadConfigDNSResolvers(t *testing.T) {
	// JSON loading test
	configJSON := `{
		"dns_resolvers": ["1.1.1.1:53", "8.8.8.8:53"]
	}`
	configPath := createTempConfig(t, configJSON)
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

	cfg := Load()
	expected := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if !reflect.DeepEqual(cfg.DNSResolvers, expected) {
		t.Errorf("Expected DNSResolvers %v, got %v", expected, cfg.DNSResolvers)
	}

	// Env override test
	os.Setenv("DNS_RESOLVERS", "9.9.9.9:53,4.2.2.2:53")
	defer os.Unsetenv("DNS_RESOLVERS")
	cfgOverride := Load()
	expectedOverride := []string{"9.9.9.9:53", "4.2.2.2:53"}
	if !reflect.DeepEqual(cfgOverride.DNSResolvers, expectedOverride) {
		t.Errorf("Expected DNSResolvers %v, got %v", expectedOverride, cfgOverride.DNSResolvers)
	}
}

func TestSaveConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-save-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	savePath := filepath.Join(tmpDir, "saved_config.json")

	cfg := &Config{
		Port:               "8080",
		Env:                "development",
		ACMEProvider:       "letsencrypt",
		CertStorageDir:     "./certs",
		ChallengePort:      "5002",
		ACMEEmail:          "admin@example.com",
		RenewThresholdDays: 30,
		CheckIntervalHours: 24,
		Certificates: []CertConfig{
			{
				ID:      "019035a1-7b00-7521-8280-60b6adbf47eb",
				Primary: "example.com",
				Sans:    []string{"*.example.com"},
				TeamID:  "019035a1-7b00-7521-8280-60b6adbf47ed",
			},
		},
		APIKeys: []APIKeyConfig{
			{
				ID:             "019035a1-7b00-7521-8280-60b6adbf47ec",
				Token:          "hashed-token",
				AllowedDomains: []string{"example.com"},
				AllowedTeams:   []string{"019035a1-7b00-7521-8280-60b6adbf47ed"},
				Admin:          true,
			},
		},
		Teams: []TeamConfig{
			{
				ID:          "019035a1-7b00-7521-8280-60b6adbf47ed",
				Name:        "Dev Team",
				Description: "Development environment",
			},
		},
	}

	if err := cfg.Save(savePath); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify the file was written and can be correctly loaded back
	os.Setenv("CONFIG_PATH", savePath)
	defer os.Unsetenv("CONFIG_PATH")

	loadedCfg := Load()

	if loadedCfg.Port != cfg.Port {
		t.Errorf("Expected Port %q, got %q", cfg.Port, loadedCfg.Port)
	}
	if loadedCfg.ACMEEmail != cfg.ACMEEmail {
		t.Errorf("Expected ACMEEmail %q, got %q", cfg.ACMEEmail, loadedCfg.ACMEEmail)
	}
	if !reflect.DeepEqual(loadedCfg.Certificates, cfg.Certificates) {
		t.Errorf("Expected Certificates %+v, got %+v", cfg.Certificates, loadedCfg.Certificates)
	}
	if !reflect.DeepEqual(loadedCfg.APIKeys, cfg.APIKeys) {
		t.Errorf("Expected APIKeys %+v, got %+v", cfg.APIKeys, loadedCfg.APIKeys)
	}
	if !reflect.DeepEqual(loadedCfg.Teams, cfg.Teams) {
		t.Errorf("Expected Teams %+v, got %+v", cfg.Teams, loadedCfg.Teams)
	}
}

func TestLoadConfig_MissingStaticID_Exit(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		configJSON := `{
			"certificates": [
				{
					"primary": "missing-id.com"
				}
			]
		}`
		configPath := createTempConfig(t, configJSON)
		os.Setenv("CONFIG_PATH", configPath)
		Load()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestLoadConfig_MissingStaticID_Exit")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestLoadConfig_StaticDynamicSplit(t *testing.T) {
	configJSON := `{
		"certificates": [
			{
				"id": "static-cert-1",
				"primary": "static.com",
				"team_id": "team-1"
			},
			{
				"id": "static-cert-no-team",
				"primary": "static-noteam.com"
			}
		],
		"api_keys": [
			{
				"id": "static-key-1",
				"token": "tok1"
			}
		],
		"teams": [
			{
				"id": "team-1",
				"name": "Team 1"
			}
		]
	}`

	configPath := createTempConfig(t, configJSON)
	os.Setenv("CONFIG_PATH", configPath)
	defer os.Unsetenv("CONFIG_PATH")

	// Create state.json in the same directory
	stateDir := filepath.Dir(configPath)
	statePath := filepath.Join(stateDir, "state.json")
	stateJSON := `{
		"certificates": [
			{
				"id": "dynamic-cert-1",
				"primary": "dynamic.com",
				"team_id": "team-1"
			},
			{
				"id": "dynamic-cert-no-team",
				"primary": "dynamic-noteam.com"
			}
		],
		"api_keys": [
			{
				"token": "tok2"
			}
		],
		"teams": [
			{
				"id": "team-2",
				"name": "Team 2"
			}
		]
	}`
	if err := os.WriteFile(statePath, []byte(stateJSON), 0644); err != nil {
		t.Fatalf("failed to write state.json: %v", err)
	}

	cfg := Load()

	// Assert merging on AllCertificates
	allCerts := cfg.AllCertificates()
	if len(allCerts) != 4 {
		t.Errorf("expected 4 certificates in total, got %d", len(allCerts))
	}

	// Assert coercion of empty TeamID to "system"
	for _, cert := range allCerts {
		if cert.ID == "static-cert-no-team" || cert.ID == "dynamic-cert-no-team" {
			if cert.TeamID != "system" {
				t.Errorf("expected TeamID for %s to be coerced to 'system', got %q", cert.ID, cert.TeamID)
			}
		}
	}

	// Assert merging on AllAPIKeys & check auto-generation of missing dynamic ID
	allKeys := cfg.AllAPIKeys()
	if len(allKeys) != 2 {
		t.Errorf("expected 2 API keys, got %d", len(allKeys))
	}
	var dynamicKey APIKeyConfig
	for _, key := range allKeys {
		if key.ID != "static-key-1" {
			dynamicKey = key
		}
	}
	if dynamicKey.ID == "" {
		t.Errorf("expected auto-generated ID for dynamic key, got empty")
	}

	// Assert merging on AllTeams and presence of built-in system team
	allTeams := cfg.AllTeams()
	if len(allTeams) != 3 { // system + team-1 + team-2
		t.Errorf("expected 3 teams, got %d: %+v", len(allTeams), allTeams)
	}
	if allTeams[0].ID != "system" {
		t.Errorf("expected system team to be the first in AllTeams(), got %q", allTeams[0].ID)
	}

	// Test SaveState
	cfg.State.Certificates = append(cfg.State.Certificates, CertConfig{
		ID:      "dynamic-cert-2",
		Primary: "new-dynamic.com",
		TeamID:  "team-2",
	})
	if err := cfg.SaveState(); err != nil {
		t.Fatalf("failed to save state: %v", err)
	}

	// Reload configuration and check that new dynamic cert is loaded
	cfg2 := Load()
	if len(cfg2.State.Certificates) != 3 {
		t.Errorf("expected 3 dynamic certificates after reload, got %d", len(cfg2.State.Certificates))
	}
}

func TestLoadConfig_SSL(t *testing.T) {
	// 1. JSON parsing and default values
	t.Run("json_parsing_and_defaults", func(t *testing.T) {
		configJSON := `{
			"ssl_cert_id": "019035a1-7b00-7521-8280-60b6adbf47eb"
		}`
		configPath := createTempConfig(t, configJSON)
		os.Setenv("CONFIG_PATH", configPath)
		defer os.Unsetenv("CONFIG_PATH")

		cfg := Load()
		if cfg.SSLCertID != "019035a1-7b00-7521-8280-60b6adbf47eb" {
			t.Errorf("Expected SSLCertID '019035a1-7b00-7521-8280-60b6adbf47eb', got %q", cfg.SSLCertID)
		}
		if cfg.HTTPSPort != "8443" {
			t.Errorf("Expected default HTTPSPort '8443', got %q", cfg.HTTPSPort)
		}
	})

	// 2. Explicit https_port in JSON
	t.Run("explicit_https_port_in_json", func(t *testing.T) {
		configJSON := `{
			"https_port": "9443",
			"ssl_cert_id": "019035a1-7b00-7521-8280-60b6adbf47eb"
		}`
		configPath := createTempConfig(t, configJSON)
		os.Setenv("CONFIG_PATH", configPath)
		defer os.Unsetenv("CONFIG_PATH")

		cfg := Load()
		if cfg.HTTPSPort != "9443" {
			t.Errorf("Expected HTTPSPort '9443', got %q", cfg.HTTPSPort)
		}
	})

	// 3. Env override for HTTPS_PORT and static check for SSL_CERT_ID (no env override for it)
	t.Run("env_override_https_port", func(t *testing.T) {
		configJSON := `{
			"https_port": "9443",
			"ssl_cert_id": "019035a1-7b00-7521-8280-60b6adbf47eb"
		}`
		configPath := createTempConfig(t, configJSON)
		os.Setenv("CONFIG_PATH", configPath)
		os.Setenv("HTTPS_PORT", "9999")
		os.Setenv("SSL_CERT_ID", "should-not-override")
		defer func() {
			os.Unsetenv("CONFIG_PATH")
			os.Unsetenv("HTTPS_PORT")
			os.Unsetenv("SSL_CERT_ID")
		}()

		cfg := Load()
		if cfg.HTTPSPort != "9999" {
			t.Errorf("Expected HTTPSPort '9999' from env override, got %q", cfg.HTTPSPort)
		}
		// ssl_cert_id must remain the one from JSON, ignoring the env variable
		if cfg.SSLCertID != "019035a1-7b00-7521-8280-60b6adbf47eb" {
			t.Errorf("Expected SSLCertID '019035a1-7b00-7521-8280-60b6adbf47eb' from JSON, got %q", cfg.SSLCertID)
		}
	})
}



