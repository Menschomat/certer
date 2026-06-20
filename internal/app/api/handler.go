package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cert-central/internal/app/config"
)

type contextKey string

const allowedDomainsKey contextKey = "allowed_domains"
const allowedTeamsKey contextKey = "allowed_teams"

func allowedDomainsFromContext(ctx context.Context) []string {
	if val, ok := ctx.Value(allowedDomainsKey).([]string); ok && val != nil {
		return val
	}
	return []string{}
}

func allowedTeamsFromContext(ctx context.Context) []string {
	if val, ok := ctx.Value(allowedTeamsKey).([]string); ok && val != nil {
		return val
	}
	return []string{}
}

// ConfigReloader defines the interface to reload scheduler configuration.
type ConfigReloader interface {
	ReloadConfig(ctx context.Context, certificates []config.CertConfig)
}

// Server handles API routes and dependencies.
type Server struct {
	mu         sync.RWMutex
	storageDir string
	cfg        *config.Config
	reloader   ConfigReloader
}

// NewServer creates a new Server instance.
func NewServer(storageDir string, cfg *config.Config, reloader ConfigReloader) *Server {
	return &Server{
		storageDir: storageDir,
		cfg:        cfg,
		reloader:   reloader,
	}
}

// Routes sets up native http.ServeMux and returns configured handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/hello", s.handleHello)
	mux.Handle("GET /api/v1/certificates", s.Authenticate(http.HandlerFunc(s.handleGetCertificates)))

	// Control plane APIs (Certificates)
	mux.Handle("GET /api/v1/config/certificates", s.Authenticate(http.HandlerFunc(s.handleGetConfigCertificates)))
	mux.Handle("POST /api/v1/config/certificates", s.Authenticate(http.HandlerFunc(s.handlePostConfigCertificates)))
	mux.Handle("PUT /api/v1/config/certificates/{id}", s.Authenticate(http.HandlerFunc(s.handlePutConfigCertificates)))
	mux.Handle("DELETE /api/v1/config/certificates/{id}", s.Authenticate(http.HandlerFunc(s.handleDeleteConfigCertificates)))

	// Control plane APIs (API Keys)
	mux.Handle("GET /api/v1/config/api_keys", s.Authenticate(http.HandlerFunc(s.handleGetConfigAPIKeys)))
	mux.Handle("POST /api/v1/config/api_keys", s.Authenticate(http.HandlerFunc(s.handlePostConfigAPIKeys)))
	mux.Handle("PUT /api/v1/config/api_keys/{id}", s.Authenticate(http.HandlerFunc(s.handlePutConfigAPIKeys)))
	mux.Handle("DELETE /api/v1/config/api_keys/{id}", s.Authenticate(http.HandlerFunc(s.handleDeleteConfigAPIKeys)))

	// Control plane APIs (Teams)
	mux.Handle("GET /api/v1/config/teams", s.Authenticate(http.HandlerFunc(s.handleGetConfigTeams)))
	mux.Handle("POST /api/v1/config/teams", s.Authenticate(http.HandlerFunc(s.handlePostConfigTeams)))
	mux.Handle("PUT /api/v1/config/teams/{id}", s.Authenticate(http.HandlerFunc(s.handlePutConfigTeams)))
	mux.Handle("DELETE /api/v1/config/teams/{id}", s.Authenticate(http.HandlerFunc(s.handleDeleteConfigTeams)))

	return mux
}

// HelloResponse is JSON response for hello endpoint.
type HelloResponse struct {
	Message string `json:"message"`
}

// CertificateResponse represents the JSON schema for sharing certificates.
type CertificateResponse struct {
	ID           string   `json:"id"`
	Domain       string   `json:"domain"`
	Sans         []string `json:"sans"`
	Issued       bool     `json:"issued"`
	Certificate  string   `json:"certificate,omitempty"`
	PrivateKey   string   `json:"private_key,omitempty"`
	CertFilename string   `json:"cert_filename,omitempty"`
	KeyFilename  string   `json:"key_filename,omitempty"`
}

// APIKeyResponse represents the API key response with cleartext token.
type APIKeyResponse struct {
	ID             string   `json:"id"`
	Token          string   `json:"token"`
	CleartextToken string   `json:"cleartext_token"`
	Description    string   `json:"description"`
	AllowedDomains []string `json:"allowed_domains"`
	AllowedTeams   []string `json:"allowed_teams"`
	Admin          bool     `json:"admin"`
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("Failed to encode JSON response", "error", err)
	}
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// Authenticate is a middleware that validates Bearer token authentication
// and injects allowed domains into the request context.
func (s *Server) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")

		if token == "" {
			slog.Warn("Unauthorized access attempt: missing token", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
			respondWithError(w, http.StatusUnauthorized, "missing authorization token")
			return
		}

		var matchedKey *config.APIKeyConfig
		s.mu.RLock()
		for _, key := range s.cfg.APIKeys {
			if key.Token != "" {
				if match, err := VerifyToken(token, key.Token); err == nil && match {
					tempKey := key
					matchedKey = &tempKey
					break
				}
			}
		}
		s.mu.RUnlock()

		if matchedKey == nil {
			tokenPrefix := token
			if len(token) > 5 {
				tokenPrefix = token[:5]
			}
			slog.Warn("Unauthorized access attempt: invalid token", "remote_addr", r.RemoteAddr, "path", r.URL.Path, "token_prefix", tokenPrefix)
			respondWithError(w, http.StatusUnauthorized, "invalid authorization token")
			return
		}

		isConfigPath := strings.HasPrefix(r.URL.Path, "/api/v1/config")

		if matchedKey.Admin {
			if !isConfigPath {
				slog.Warn("Forbidden access attempt: admin token tried to access non-config route", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
				respondWithError(w, http.StatusForbidden, "admin tokens are restricted to config APIs only")
				return
			}
		} else {
			if isConfigPath {
				slog.Warn("Forbidden access attempt: fetch token tried to access config route", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
				respondWithError(w, http.StatusForbidden, "fetch tokens are restricted from configuration APIs")
				return
			}
		}

		allowedDomains := matchedKey.AllowedDomains
		if allowedDomains == nil {
			allowedDomains = []string{}
		}
		allowedTeams := matchedKey.AllowedTeams
		if allowedTeams == nil {
			allowedTeams = []string{}
		}

		ctx := context.WithValue(r.Context(), allowedDomainsKey, allowedDomains)
		ctx = context.WithValue(ctx, allowedTeamsKey, allowedTeams)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) handleGetCertificates(w http.ResponseWriter, r *http.Request) {
	allowedDomains := allowedDomainsFromContext(r.Context())
	allowedTeams := allowedTeamsFromContext(r.Context())

	respList := []CertificateResponse{}

	s.mu.RLock()
	certs := make([]config.CertConfig, len(s.cfg.Certificates))
	copy(certs, s.cfg.Certificates)
	s.mu.RUnlock()

	for _, cc := range certs {
		if cc.Primary == "" {
			continue
		}

		// Only return certificates for domains authorized by the token
		if !isDomainAllowed(cc.Primary, allowedDomains) {
			continue
		}

		// Only return certificates for teams authorized by the token
		if !isTeamAllowed(cc.TeamID, allowedTeams) {
			continue
		}

		certPath := filepath.Join(s.storageDir, cc.ID+".crt")
		keyPath := filepath.Join(s.storageDir, cc.ID+".key")

		resp := CertificateResponse{
			ID:           cc.ID,
			Domain:       cc.Primary,
			Sans:         cc.Sans,
			Issued:       false,
			CertFilename: cc.Primary + ".crt",
			KeyFilename:  cc.Primary + ".key",
		}

		if certBytes, err := os.ReadFile(certPath); err == nil {
			resp.Certificate = string(certBytes)
		}
		if keyBytes, err := os.ReadFile(keyPath); err == nil && resp.Certificate != "" {
			resp.PrivateKey = string(keyBytes)
			resp.Issued = true
		}

		respList = append(respList, resp)
	}

	respondWithJSON(w, http.StatusOK, respList)
}

func isTeamAllowed(teamID string, allowedTeams []string) bool {
	if teamID == "" && len(allowedTeams) == 0 {
		return true
	}
	for _, t := range allowedTeams {
		if t == teamID {
			return true
		}
	}
	return false
}

func isDomainAllowed(domain string, allowed []string) bool {
	for _, a := range allowed {
		if a == domain {
			return true
		}
	}
	return false
}

func (s *Server) handleHello(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, HelloResponse{Message: "Hello, World!"})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"up"}`))
}

// ReloadConfig updates the server's certificates and API keys in a thread-safe manner.
func (s *Server) ReloadConfig(certificates []config.CertConfig, apiKeys []config.APIKeyConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Certificates = certificates
	s.cfg.APIKeys = apiKeys
}

func (s *Server) saveAndReload(ctx context.Context) error {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.json"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Save config to disk
	if err := s.cfg.Save(configPath); err != nil {
		slog.Error("Failed to save config on disk", "error", err)
		return err
	}

	// 2. Reload scheduler (if present)
	if s.reloader != nil {
		certs := make([]config.CertConfig, len(s.cfg.Certificates))
		copy(certs, s.cfg.Certificates)
		s.reloader.ReloadConfig(ctx, certs)
	}

	return nil
}

func (s *Server) handleGetConfigCertificates(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	certs := make([]config.CertConfig, len(s.cfg.Certificates))
	copy(certs, s.cfg.Certificates)
	s.mu.RUnlock()

	respondWithJSON(w, http.StatusOK, certs)
}

func (s *Server) handlePostConfigCertificates(w http.ResponseWriter, r *http.Request) {
	payload, ok := decodeBody[config.CertConfig](w, r)
	if !ok {
		return
	}
	if payload.Primary == "" {
		respondWithError(w, http.StatusBadRequest, "primary domain is required")
		return
	}
	s.mu.RLock()
	validTeam := isValidTeam(s.cfg, payload.TeamID)
	s.mu.RUnlock()
	if !validTeam {
		respondWithError(w, http.StatusBadRequest, "invalid or missing team_id")
		return
	}

	uuidStr, err := GenerateUUIDv7()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to generate ID")
		return
	}
	payload.ID = uuidStr

	s.mu.Lock()
	s.cfg.Certificates = append(s.cfg.Certificates, payload)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	respondWithJSON(w, http.StatusCreated, payload)
}

func (s *Server) handlePutConfigCertificates(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondWithError(w, http.StatusBadRequest, "id parameter is required")
		return
	}

	payload, ok := decodeBody[config.CertConfig](w, r)
	if !ok {
		return
	}
	s.mu.RLock()
	validTeam := isValidTeam(s.cfg, payload.TeamID)
	s.mu.RUnlock()
	if !validTeam {
		respondWithError(w, http.StatusBadRequest, "invalid or missing team_id")
		return
	}

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.Certificates, id, func(c config.CertConfig) string { return c.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "certificate configuration not found")
		return
	}

	s.cfg.Certificates[foundIdx].Primary = payload.Primary
	s.cfg.Certificates[foundIdx].Sans = payload.Sans
	s.cfg.Certificates[foundIdx].TeamID = payload.TeamID
	s.cfg.Certificates[foundIdx].Description = payload.Description
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteConfigCertificates(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondWithError(w, http.StatusBadRequest, "id parameter is required")
		return
	}

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.Certificates, id, func(c config.CertConfig) string { return c.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "certificate configuration not found")
		return
	}

	s.cfg.Certificates = removeAtIndex(s.cfg.Certificates, foundIdx)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetConfigAPIKeys(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	keys := make([]config.APIKeyConfig, len(s.cfg.APIKeys))
	copy(keys, s.cfg.APIKeys)
	s.mu.RUnlock()

	respondWithJSON(w, http.StatusOK, keys)
}

func (s *Server) handlePostConfigAPIKeys(w http.ResponseWriter, r *http.Request) {
	payload, ok := decodeBody[config.APIKeyConfig](w, r)
	if !ok {
		return
	}
	s.mu.RLock()
	validTeams := areTeamsValid(s.cfg, payload.AllowedTeams)
	s.mu.RUnlock()
	if !validTeams {
		respondWithError(w, http.StatusBadRequest, "one or more allowed_teams are invalid")
		return
	}

	uuidStr, err := GenerateUUIDv7()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to generate ID")
		return
	}
	payload.ID = uuidStr

	// Generate 32-byte secure token (64 hex characters)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to generate random token")
		return
	}
	cleartextToken := hex.EncodeToString(bytes)

	hash, err := GenerateArgon2idHash(cleartextToken)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to hash token")
		return
	}
	payload.Token = hash

	s.mu.Lock()
	s.cfg.APIKeys = append(s.cfg.APIKeys, payload)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	resp := APIKeyResponse{
		ID:             payload.ID,
		Token:          payload.Token,
		CleartextToken: cleartextToken,
		Description:    payload.Description,
		AllowedDomains: payload.AllowedDomains,
		AllowedTeams:   payload.AllowedTeams,
		Admin:          payload.Admin,
	}

	respondWithJSON(w, http.StatusCreated, resp)
}

func (s *Server) handlePutConfigAPIKeys(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondWithError(w, http.StatusBadRequest, "id parameter is required")
		return
	}

	payload, ok := decodeBody[config.APIKeyConfig](w, r)
	if !ok {
		return
	}
	s.mu.RLock()
	validTeams := areTeamsValid(s.cfg, payload.AllowedTeams)
	s.mu.RUnlock()
	if !validTeams {
		respondWithError(w, http.StatusBadRequest, "one or more allowed_teams are invalid")
		return
	}

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.APIKeys, id, func(k config.APIKeyConfig) string { return k.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "API key configuration not found")
		return
	}

	s.cfg.APIKeys[foundIdx].AllowedDomains = payload.AllowedDomains
	s.cfg.APIKeys[foundIdx].AllowedTeams = payload.AllowedTeams
	s.cfg.APIKeys[foundIdx].Admin = payload.Admin
	s.cfg.APIKeys[foundIdx].Description = payload.Description
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteConfigAPIKeys(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondWithError(w, http.StatusBadRequest, "id parameter is required")
		return
	}

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.APIKeys, id, func(k config.APIKeyConfig) string { return k.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "API key configuration not found")
		return
	}

	s.cfg.APIKeys = removeAtIndex(s.cfg.APIKeys, foundIdx)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func isValidTeam(cfg *config.Config, teamID string) bool {
	if teamID == "" {
		return false
	}
	for _, t := range cfg.Teams {
		if t.ID == teamID {
			return true
		}
	}
	return false
}

func areTeamsValid(cfg *config.Config, teamIDs []string) bool {
	for _, teamID := range teamIDs {
		if !isValidTeam(cfg, teamID) {
			return false
		}
	}
	return true
}

func (s *Server) handleGetConfigTeams(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	teams := make([]config.TeamConfig, len(s.cfg.Teams))
	copy(teams, s.cfg.Teams)
	s.mu.RUnlock()

	respondWithJSON(w, http.StatusOK, teams)
}

func (s *Server) handlePostConfigTeams(w http.ResponseWriter, r *http.Request) {
	payload, ok := decodeBody[config.TeamConfig](w, r)
	if !ok {
		return
	}
	if payload.Name == "" {
		respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}

	uuidStr, err := GenerateUUIDv7()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to generate ID")
		return
	}
	payload.ID = uuidStr

	s.mu.Lock()
	s.cfg.Teams = append(s.cfg.Teams, payload)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	respondWithJSON(w, http.StatusCreated, payload)
}

func (s *Server) handlePutConfigTeams(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondWithError(w, http.StatusBadRequest, "id parameter is required")
		return
	}

	payload, ok := decodeBody[config.TeamConfig](w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.Teams, id, func(t config.TeamConfig) string { return t.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "team configuration not found")
		return
	}

	s.cfg.Teams[foundIdx].Name = payload.Name
	s.cfg.Teams[foundIdx].Description = payload.Description
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteConfigTeams(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondWithError(w, http.StatusBadRequest, "id parameter is required")
		return
	}

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.Teams, id, func(t config.TeamConfig) string { return t.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "team configuration not found")
		return
	}

	// Referential integrity check: check if the team is in use by any certificates or API keys
	for _, cert := range s.cfg.Certificates {
		if cert.TeamID == id {
			s.mu.Unlock()
			respondWithError(w, http.StatusBadRequest, "cannot delete team that is in use by certificates")
			return
		}
	}
	for _, key := range s.cfg.APIKeys {
		for _, allowedTeam := range key.AllowedTeams {
			if allowedTeam == id {
				s.mu.Unlock()
				respondWithError(w, http.StatusBadRequest, "cannot delete team that is in use by API keys")
				return
			}
		}
	}

	s.cfg.Teams = removeAtIndex(s.cfg.Teams, foundIdx)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func decodeBody[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var payload T
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		var zero T
		return zero, false
	}
	return payload, true
}

func findByID[T any](slice []T, id string, getID func(T) string) (int, bool) {
	for idx, item := range slice {
		if getID(item) == id {
			return idx, true
		}
	}
	return -1, false
}

func removeAtIndex[T any](slice []T, idx int) []T {
	return append(slice[:idx], slice[idx+1:]...)
}
