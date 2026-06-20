package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// TeamConfig configures first-class team metadata.
type TeamConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CertConfig configures primary domain and its SANs.
type CertConfig struct {
	ID          string   `json:"id"`
	Primary     string   `json:"primary"`
	Sans        []string `json:"sans"`
	TeamID      string   `json:"team_id"`
	Description string   `json:"description"`
}

// APIKeyConfig defines token to domain mapping.
type APIKeyConfig struct {
	ID             string   `json:"id"`
	Token          string   `json:"token"`
	Description    string   `json:"description"`
	AllowedDomains []string `json:"allowed_domains"`
	AllowedTeams   []string `json:"allowed_teams"`
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
	Teams              []TeamConfig   `json:"teams"`
}

// Load loads configuration from environment variables with defaults.
func Load() *Config {
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
			cfg.mergeFromJSON(jsonCfg)
		} else {
			slog.Error("Failed to unmarshal config JSON", "path", configPath, "error", err)
		}
	}

	cfg.applyEnvOverrides()

	if cfg.ACMEDirectoryURL == "" {
		cfg.ACMEDirectoryURL = defaultACMEURL(cfg.ACMEProvider, cfg.Env)
	}

	if cfg.ensureIDs() {
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

func mergeString(dst *string, src string) {
	if src != "" {
		*dst = src
	}
}

func mergeInt(dst *int, src int) {
	if src > 0 {
		*dst = src
	}
}

func mergeSlice[T any](dst *[]T, src []T) {
	if len(src) > 0 {
		*dst = src
	}
}

func (cfg *Config) mergeFromJSON(jsonCfg Config) {
	mergeString(&cfg.Port, jsonCfg.Port)
	mergeString(&cfg.Env, jsonCfg.Env)
	mergeString(&cfg.ACMEProvider, jsonCfg.ACMEProvider)
	mergeString(&cfg.ACMEDirectoryURL, jsonCfg.ACMEDirectoryURL)
	mergeString(&cfg.EABKid, jsonCfg.EABKid)
	mergeString(&cfg.EABHmac, jsonCfg.EABHmac)
	mergeString(&cfg.CertStorageDir, jsonCfg.CertStorageDir)
	mergeString(&cfg.ChallengePort, jsonCfg.ChallengePort)
	mergeString(&cfg.ACMEEmail, jsonCfg.ACMEEmail)
	mergeString(&cfg.DNSProvider, jsonCfg.DNSProvider)
	mergeSlice(&cfg.DNSResolvers, jsonCfg.DNSResolvers)
	mergeInt(&cfg.RenewThresholdDays, jsonCfg.RenewThresholdDays)
	mergeInt(&cfg.CheckIntervalHours, jsonCfg.CheckIntervalHours)
	mergeSlice(&cfg.Certificates, jsonCfg.Certificates)
	mergeSlice(&cfg.APIKeys, jsonCfg.APIKeys)
	mergeSlice(&cfg.Teams, jsonCfg.Teams)
}

func (cfg *Config) applyEnvOverrides() {
	mergeString(&cfg.Port, os.Getenv("PORT"))
	mergeString(&cfg.Env, os.Getenv("ENV"))
	mergeString(&cfg.ACMEProvider, os.Getenv("ACME_PROVIDER"))
	mergeString(&cfg.ACMEDirectoryURL, os.Getenv("ACME_DIRECTORY_URL"))
	mergeString(&cfg.EABKid, os.Getenv("EAB_KID"))
	mergeString(&cfg.EABHmac, os.Getenv("EAB_HMAC"))
	mergeString(&cfg.CertStorageDir, os.Getenv("CERT_STORAGE_DIR"))
	mergeString(&cfg.ChallengePort, os.Getenv("CHALLENGE_PORT"))
	mergeString(&cfg.ACMEEmail, os.Getenv("ACME_EMAIL"))
	mergeString(&cfg.DNSProvider, os.Getenv("DNS_PROVIDER"))

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
}

func (cfg *Config) ensureIDs() bool {
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
	for i := range cfg.Teams {
		if cfg.Teams[i].ID == "" {
			if id, err := uuid.NewV7(); err == nil {
				cfg.Teams[i].ID = id.String()
				dirty = true
			}
		}
	}
	return dirty
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

