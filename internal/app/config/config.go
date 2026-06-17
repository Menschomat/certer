package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
)

// CertConfig configures primary domain and its SANs.
type CertConfig struct {
	Primary string   `json:"primary"`
	Sans    []string `json:"sans"`
}

// APIKeyConfig defines token to domain mapping.
type APIKeyConfig struct {
	Token          string   `json:"token"`
	AllowedDomains []string `json:"allowed_domains"`
}

// Config holds application configuration.
type Config struct {
	Port               string         `json:"port"`
	Env                string         `json:"env"`
	ACMEDirectoryURL   string         `json:"acme_directory_url"`
	CertStorageDir     string         `json:"cert_storage_dir"`
	ChallengePort      string         `json:"challenge_port"`
	ACMEEmail          string         `json:"acme_email"`
	Certificates       []CertConfig   `json:"certificates"`
	DNSProvider        string         `json:"dns_provider"`
	RenewThresholdDays int            `json:"renew_threshold_days"`
	CheckIntervalHours int            `json:"check_interval_hours"`
	APIKeys            []APIKeyConfig `json:"api_keys"`
}

// Load loads configuration from environment variables with defaults.
func Load() *Config {
	// Defaults
	cfg := &Config{
		Port:               "8080",
		Env:                "development",
		ACMEDirectoryURL:   "https://acme-staging-v02.api.letsencrypt.org/directory",
		CertStorageDir:     "./certs",
		ChallengePort:      "5002",
		RenewThresholdDays: 30,
		CheckIntervalHours: 24,
	}

	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.json"
	}

	if data, err := os.ReadFile(configPath); err == nil {
		var jsonCfg Config
		if err := json.Unmarshal(data, &jsonCfg); err == nil {
			if jsonCfg.Port != "" {
				cfg.Port = jsonCfg.Port
			}
			if jsonCfg.Env != "" {
				cfg.Env = jsonCfg.Env
			}
			if jsonCfg.ACMEDirectoryURL != "" {
				cfg.ACMEDirectoryURL = jsonCfg.ACMEDirectoryURL
			}
			if jsonCfg.CertStorageDir != "" {
				cfg.CertStorageDir = jsonCfg.CertStorageDir
			}
			if jsonCfg.ChallengePort != "" {
				cfg.ChallengePort = jsonCfg.ChallengePort
			}
			if jsonCfg.ACMEEmail != "" {
				cfg.ACMEEmail = jsonCfg.ACMEEmail
			}
			if jsonCfg.DNSProvider != "" {
				cfg.DNSProvider = jsonCfg.DNSProvider
			}
			if jsonCfg.RenewThresholdDays > 0 {
				cfg.RenewThresholdDays = jsonCfg.RenewThresholdDays
			}
			if jsonCfg.CheckIntervalHours > 0 {
				cfg.CheckIntervalHours = jsonCfg.CheckIntervalHours
			}
			if len(jsonCfg.Certificates) > 0 {
				cfg.Certificates = jsonCfg.Certificates
			}
			if len(jsonCfg.APIKeys) > 0 {
				cfg.APIKeys = jsonCfg.APIKeys
			}
		} else {
			slog.Error("Failed to unmarshal config JSON", "path", configPath, "error", err)
		}
	} else {
		// Fallback to environment variables
		if envPort := os.Getenv("PORT"); envPort != "" {
			cfg.Port = envPort
		}
		if envEnv := os.Getenv("ENV"); envEnv != "" {
			cfg.Env = envEnv
		}
		if envACME := os.Getenv("ACME_DIRECTORY_URL"); envACME != "" {
			cfg.ACMEDirectoryURL = envACME
		}
		if envStorage := os.Getenv("CERT_STORAGE_DIR"); envStorage != "" {
			cfg.CertStorageDir = envStorage
		}
		if envChallenge := os.Getenv("CHALLENGE_PORT"); envChallenge != "" {
			cfg.ChallengePort = envChallenge
		}
		if envEmail := os.Getenv("ACME_EMAIL"); envEmail != "" {
			cfg.ACMEEmail = envEmail
		}
		if envDNS := os.Getenv("DNS_PROVIDER"); envDNS != "" {
			cfg.DNSProvider = envDNS
		}
		if envRenew := os.Getenv("RENEW_THRESHOLD_DAYS"); envRenew != "" {
			if val, err := strconv.Atoi(envRenew); err == nil {
				cfg.RenewThresholdDays = val
			}
		}
		if envCheck := os.Getenv("CHECK_INTERVAL_HOURS"); envCheck != "" {
			if val, err := strconv.Atoi(envCheck); err == nil {
				cfg.CheckIntervalHours = val
			}
		}
	}

	return cfg
}
