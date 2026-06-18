package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"cert-central/internal/app/config"
)

type contextKey string

const allowedDomainsKey contextKey = "allowed_domains"

// Server handles API routes and dependencies.
type Server struct {
	storageDir   string
	certificates []config.CertConfig
	apiKeys      []config.APIKeyConfig
}

// NewServer creates a new Server instance.
func NewServer(storageDir string, certificates []config.CertConfig, apiKeys []config.APIKeyConfig) *Server {
	return &Server{
		storageDir:   storageDir,
		certificates: certificates,
		apiKeys:      apiKeys,
	}
}

// Routes sets up native http.ServeMux and returns configured handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/hello", s.handleHello)
	mux.Handle("GET /api/v1/certificates", s.Authenticate(http.HandlerFunc(s.handleGetCertificates)))

	return mux
}

// HelloResponse is JSON response for hello endpoint.
type HelloResponse struct {
	Message string `json:"message"`
}

// CertificateResponse represents the JSON schema for sharing certificates.
type CertificateResponse struct {
	Domain      string   `json:"domain"`
	Sans        []string `json:"sans"`
	Issued      bool     `json:"issued"`
	Certificate string   `json:"certificate,omitempty"`
	PrivateKey  string   `json:"private_key,omitempty"`
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// Authenticate is a middleware that validates Bearer token authentication
// and injects allowed domains into the request context.
func (s *Server) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := ""
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			token = authHeader
		}

		if token == "" {
			respondWithError(w, http.StatusUnauthorized, "missing authorization token")
			return
		}

		var allowedDomains []string
		authorized := false
		for _, key := range s.apiKeys {
			if key.Token != "" {
				if match, err := VerifyToken(token, key.Token); err == nil && match {
					allowedDomains = key.AllowedDomains
					authorized = true
					break
				}
			}
		}

		if !authorized {
			respondWithError(w, http.StatusUnauthorized, "invalid authorization token")
			return
		}

		ctx := context.WithValue(r.Context(), allowedDomainsKey, allowedDomains)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) handleGetCertificates(w http.ResponseWriter, r *http.Request) {
	allowedDomains, ok := r.Context().Value(allowedDomainsKey).([]string)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "failed to parse authorization context")
		return
	}

	respList := []CertificateResponse{}

	for _, cc := range s.certificates {
		if cc.Primary == "" {
			continue
		}

		// Only return certificates for domains authorized by the token
		if !isDomainAllowed(cc.Primary, allowedDomains) {
			continue
		}

		certPath := filepath.Join(s.storageDir, cc.Primary+".crt")
		keyPath := filepath.Join(s.storageDir, cc.Primary+".key")

		resp := CertificateResponse{
			Domain: cc.Primary,
			Sans:   cc.Sans,
			Issued: false,
		}

		certBytes, err := os.ReadFile(certPath)
		if err == nil {
			resp.Certificate = string(certBytes)
			keyBytes, err := os.ReadFile(keyPath)
			if err == nil {
				resp.PrivateKey = string(keyBytes)
				resp.Issued = true
			}
		}

		respList = append(respList, resp)
	}

	respondWithJSON(w, http.StatusOK, respList)
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
