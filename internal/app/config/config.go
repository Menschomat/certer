package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// CertConfig configures primary domain and its SANs.
type CertConfig struct {
	ID          string   `json:"id"`
	Primary     string   `json:"primary"`
	Sans        []string `json:"sans"`
	Description string   `json:"description"`
}

// APIKeyConfig defines token to domain mapping.
type APIKeyConfig struct {
	ID             string   `json:"id"`
	Token          string   `json:"token"`
	Description    string   `json:"description"`
	AllowedDomains []string `json:"allowed_domains"`
	Admin          bool     `json:"admin"`
}

// Config holds application configuration.
type Config struct {
	Port               string         `json:"port"`
	Env                string         `json:"env"`
	ACMEProvider       string         `json:"acme_provider"`
	ACMEDirectoryURL   string         `json:"acme_directory_url"`
	EABKid             string         `json:"eab_kid"`
	EABHmac            string         `json:"eab_hmac"`
	CertStorageDir     string         `json:"cert_storage_dir"`
	ChallengePort      string         `json:"challenge_port"`
	ACMEEmail          string         `json:"acme_email"`
	Certificates       []CertConfig   `json:"certificates"`
	DNSProvider        string         `json:"dns_provider"`
	DNSResolvers       []string       `json:"dns_resolvers"`
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
		ACMEProvider:       "letsencrypt",
		ACMEDirectoryURL:   "",
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
			if jsonCfg.ACMEProvider != "" {
				cfg.ACMEProvider = jsonCfg.ACMEProvider
			}
			if jsonCfg.ACMEDirectoryURL != "" {
				cfg.ACMEDirectoryURL = jsonCfg.ACMEDirectoryURL
			}
			if jsonCfg.EABKid != "" {
				cfg.EABKid = jsonCfg.EABKid
			}
			if jsonCfg.EABHmac != "" {
				cfg.EABHmac = jsonCfg.EABHmac
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
			if len(jsonCfg.DNSResolvers) > 0 {
				cfg.DNSResolvers = jsonCfg.DNSResolvers
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
	}

	// Environment variables always override JSON/Defaults
	if envPort := os.Getenv("PORT"); envPort != "" {
		cfg.Port = envPort
	}
	if envEnv := os.Getenv("ENV"); envEnv != "" {
		cfg.Env = envEnv
	}
	if envProvider := os.Getenv("ACME_PROVIDER"); envProvider != "" {
		cfg.ACMEProvider = envProvider
	}
	if envACME := os.Getenv("ACME_DIRECTORY_URL"); envACME != "" {
		cfg.ACMEDirectoryURL = envACME
	}
	if envEABKid := os.Getenv("EAB_KID"); envEABKid != "" {
		cfg.EABKid = envEABKid
	}
	if envEABHmac := os.Getenv("EAB_HMAC"); envEABHmac != "" {
		cfg.EABHmac = envEABHmac
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
	if envResolvers := os.Getenv("DNS_RESOLVERS"); envResolvers != "" {
		cfg.DNSResolvers = strings.Split(envResolvers, ",")
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


	if cfg.ACMEDirectoryURL == "" {
		cfg.ACMEDirectoryURL = defaultACMEURL(cfg.ACMEProvider, cfg.Env)
	}

	dirty := false
	for i := range cfg.Certificates {
		if cfg.Certificates[i].ID == "" {
			if id, err := uuid.NewV7(); err == nil {
				cfg.Certificates[i].ID = id.String()
				dirty = true
			}
		}
	}
	for i := range cfg.APIKeys {
		if cfg.APIKeys[i].ID == "" {
			if id, err := uuid.NewV7(); err == nil {
				cfg.APIKeys[i].ID = id.String()
				dirty = true
			}
		}
	}

	if dirty {
		if _, err := os.Stat(configPath); err == nil {
			if err := cfg.Save(configPath); err != nil {
				slog.Error("Failed to save auto-generated IDs to config file", "path", configPath, "error", err)
			} else {
				slog.Info("Auto-generated and persisted missing IDs in config file", "path", configPath)
			}
		}
	}

	return cfg
}

func defaultACMEURL(provider, env string) string {
	if provider == "zerossl" {
		return "https://acme.zerossl.com/v2/DV90"
	}
	if env == "production" {
		return "https://acme-v02.api.letsencrypt.org/directory"
	}
	return "https://acme-staging-v02.api.letsencrypt.org/directory"
}

// Save serializes the configuration as indented JSON and writes it to the specified filepath.
func (c *Config) Save(filepath string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}

