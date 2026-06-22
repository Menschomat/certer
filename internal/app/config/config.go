package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	DNSProvider string   `json:"dns_provider,omitempty"`
}

// APIKeyConfig defines token mapping with certificates and teams.
type APIKeyConfig struct {
	ID                  string   `json:"id"`
	Token               string   `json:"token"`
	Description         string   `json:"description"`
	AllowedCertificates []string `json:"allowed_certificates,omitempty"`
	AllowedTeams        []string `json:"allowed_teams"`
	Admin               bool     `json:"admin"`
}

// State represents the runtime mutable configuration state.
type State struct {
	Certificates []CertConfig   `json:"certificates"`
	APIKeys      []APIKeyConfig `json:"api_keys"`
	Teams        []TeamConfig   `json:"teams"`
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
	HTTPSPort          string         `json:"https_port"`
	SSLCertID          string         `json:"ssl_cert_id"`

	State              State          `json:"-"`
	StatePath          string         `json:"-"`
}

// AllCertificates returns the union of static and dynamic certificates.
func (c *Config) AllCertificates() []CertConfig {
	res := make([]CertConfig, 0, len(c.Certificates)+len(c.State.Certificates))
	res = append(res, c.Certificates...)
	res = append(res, c.State.Certificates...)
	return res
}

// AllAPIKeys returns the union of static and dynamic API keys.
func (c *Config) AllAPIKeys() []APIKeyConfig {
	res := make([]APIKeyConfig, 0, len(c.APIKeys)+len(c.State.APIKeys))
	res = append(res, c.APIKeys...)
	res = append(res, c.State.APIKeys...)
	return res
}

// AllTeams returns the union of static and dynamic teams, prepending the system team.
func (c *Config) AllTeams() []TeamConfig {
	res := []TeamConfig{
		{
			ID:          "system",
			Name:        "System",
			Description: "System team for global/unassigned resources",
		},
	}
	res = append(res, c.Teams...)
	res = append(res, c.State.Teams...)
	return res
}

// Load loads configuration from environment variables with defaults.
func Load() (*Config, error) {
	cfg := &Config{
		Port:               "8080",
		Env:                "development",
		ACMEProvider:       "letsencrypt",
		ACMEDirectoryURL:   "",
		CertStorageDir:     "./certs",
		ChallengePort:      "5002",
		RenewThresholdDays: 30,
		CheckIntervalHours: 24,
		HTTPSPort:          "8443",
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

	// Validate static configuration items have explicit ID field on boot
	if err := cfg.validateStaticIDs(); err != nil {
		return nil, err
	}

	// Coerce static certificate team IDs to "system" if empty
	cfg.coerceStaticTeamIDs()

	// Load dynamic state
	statePath := os.Getenv("STATE_PATH")
	if statePath == "" {
		statePath = filepath.Join(filepath.Dir(configPath), "state.json")
	}
	cfg.StatePath = statePath

	var state State
	stateData, err := os.ReadFile(statePath)
	if err == nil {
		if err := json.Unmarshal(stateData, &state); err != nil {
			slog.Error("Failed to unmarshal state JSON", "path", statePath, "error", err)
		}
	} else if !os.IsNotExist(err) {
		slog.Error("Failed to read state file", "path", statePath, "error", err)
	}
	cfg.State = state

	dirty := cfg.ensureDynamicIDs()

	// Coerce dynamic cert team IDs to "system" if empty
	for i := range cfg.State.Certificates {
		if cfg.State.Certificates[i].TeamID == "" {
			cfg.State.Certificates[i].TeamID = "system"
			dirty = true
		}
	}

	if dirty {
		if err := cfg.SaveState(); err != nil {
			slog.Error("Failed to save state with generated IDs or coerced team IDs", "path", statePath, "error", err)
		}
	}

	return cfg, nil
}

// MustLoad loads configuration and exits the process on failure.
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}
	return cfg
}

func (cfg *Config) validateStaticIDs() error {
	for _, cc := range cfg.Certificates {
		if cc.ID == "" {
			return fmt.Errorf("static configuration error: certificate missing id")
		}
	}
	for _, k := range cfg.APIKeys {
		if k.ID == "" {
			return fmt.Errorf("static configuration error: api key missing id")
		}
	}
	for _, t := range cfg.Teams {
		if t.ID == "" {
			return fmt.Errorf("static configuration error: team missing id")
		}
	}
	return nil
}

func (cfg *Config) coerceStaticTeamIDs() {
	for i := range cfg.Certificates {
		if cfg.Certificates[i].TeamID == "" {
			cfg.Certificates[i].TeamID = "system"
		}
	}
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
	mergeString(&cfg.HTTPSPort, jsonCfg.HTTPSPort)
	mergeString(&cfg.SSLCertID, jsonCfg.SSLCertID)
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
	mergeString(&cfg.HTTPSPort, os.Getenv("HTTPS_PORT"))
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

func (cfg *Config) ensureDynamicIDs() bool {
	dirty := false
	for i := range cfg.State.Certificates {
		if cfg.State.Certificates[i].ID == "" {
			if id, err := uuid.NewV7(); err == nil {
				cfg.State.Certificates[i].ID = id.String()
				dirty = true
			}
		}
	}
	for i := range cfg.State.APIKeys {
		if cfg.State.APIKeys[i].ID == "" {
			if id, err := uuid.NewV7(); err == nil {
				cfg.State.APIKeys[i].ID = id.String()
				dirty = true
			}
		}
	}
	for i := range cfg.State.Teams {
		if cfg.State.Teams[i].ID == "" {
			if id, err := uuid.NewV7(); err == nil {
				cfg.State.Teams[i].ID = id.String()
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

// Save serializes the infrastructure configuration as indented JSON and writes it to the specified filepath.
func (c *Config) Save(filepath string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}

// SaveState serializes the runtime dynamic state as indented JSON.
func (c *Config) SaveState() error {
	data, err := json.MarshalIndent(c.State, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.StatePath, data, 0644)
}
