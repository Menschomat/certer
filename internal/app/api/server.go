package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"cert-central/internal/app/config"
)

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

	routes := []struct {
		pattern string
		handler http.Handler
	}{
		// Public Endpoints
		{"GET /health", http.HandlerFunc(s.handleHealth)},
		{"GET /api/v1/hello", http.HandlerFunc(s.handleHello)},

		// Scoped Certificates API
		{"GET /api/v1/certificates", s.Authenticate(http.HandlerFunc(s.handleGetCertificates))},

		// Control plane APIs (Certificates)
		{"GET /api/v1/config/certificates", s.Authenticate(http.HandlerFunc(s.handleGetConfigCertificates))},
		{"POST /api/v1/config/certificates", s.Authenticate(http.HandlerFunc(s.handlePostConfigCertificates))},
		{"PUT /api/v1/config/certificates/{id}", s.Authenticate(http.HandlerFunc(s.handlePutConfigCertificates))},
		{"DELETE /api/v1/config/certificates/{id}", s.Authenticate(http.HandlerFunc(s.handleDeleteConfigCertificates))},

		// Control plane APIs (API Keys)
		{"GET /api/v1/config/api_keys", s.Authenticate(http.HandlerFunc(s.handleGetConfigAPIKeys))},
		{"POST /api/v1/config/api_keys", s.Authenticate(http.HandlerFunc(s.handlePostConfigAPIKeys))},
		{"PUT /api/v1/config/api_keys/{id}", s.Authenticate(http.HandlerFunc(s.handlePutConfigAPIKeys))},
		{"DELETE /api/v1/config/api_keys/{id}", s.Authenticate(http.HandlerFunc(s.handleDeleteConfigAPIKeys))},

		// Control plane APIs (Teams)
		{"GET /api/v1/config/teams", s.Authenticate(http.HandlerFunc(s.handleGetConfigTeams))},
		{"POST /api/v1/config/teams", s.Authenticate(http.HandlerFunc(s.handlePostConfigTeams))},
		{"PUT /api/v1/config/teams/{id}", s.Authenticate(http.HandlerFunc(s.handlePutConfigTeams))},
		{"DELETE /api/v1/config/teams/{id}", s.Authenticate(http.HandlerFunc(s.handleDeleteConfigTeams))},
	}

	for _, r := range routes {
		mux.Handle(r.pattern, r.handler)
	}

	return mux
}

// HelloResponse is JSON response for hello endpoint.
type HelloResponse struct {
	Message string `json:"message"`
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
		allKeys := s.cfg.AllAPIKeys()
		for _, key := range allKeys {
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
	s.cfg.State.Certificates = certificates
	s.cfg.State.APIKeys = apiKeys
}

func (s *Server) saveAndReload(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Save state to disk
	if err := s.cfg.SaveState(); err != nil {
		slog.Error("Failed to save state on disk", "error", err)
		return err
	}

	// 2. Reload scheduler (if present)
	if s.reloader != nil {
		certs := s.cfg.AllCertificates()
		s.reloader.ReloadConfig(ctx, certs)
	}

	return nil
}
