package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config-tests-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")
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

	err = os.WriteFile(configPath, []byte(configJSON), 0644)
	if err != nil {
		t.Fatalf("Failed to write config.json: %v", err)
	}

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
