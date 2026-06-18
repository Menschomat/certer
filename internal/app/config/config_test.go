package config

import (
	"os"
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
				"primary": "example.com",
				"sans": ["*.example.com", "www.example.com"]
			}
		],
		"api_keys": [
			{
				"token": "blabliblub",
				"allowed_domains": ["menscho.space", "weihrauchphoto.de"]
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
			Primary: "example.com",
			Sans:    []string{"*.example.com", "www.example.com"},
		},
	}
	if !reflect.DeepEqual(cfg.Certificates, expectedCerts) {
		t.Errorf("Expected Certificates %+v, got %+v", expectedCerts, cfg.Certificates)
	}

	expectedAPIKeys := []APIKeyConfig{
		{
			Token:          "blabliblub",
			AllowedDomains: []string{"menscho.space", "weihrauchphoto.de"},
		},
	}
	if !reflect.DeepEqual(cfg.APIKeys, expectedAPIKeys) {
		t.Errorf("Expected APIKeys %+v, got %+v", expectedAPIKeys, cfg.APIKeys)
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
