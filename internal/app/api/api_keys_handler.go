package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"certer/internal/app/config"
)

// APIKeyResponse represents the API key response with cleartext token.
type APIKeyResponse struct {
	ID                  string   `json:"id"`
	Token               string   `json:"token"`
	CleartextToken      string   `json:"cleartext_token"`
	Description         string   `json:"description"`
	AllowedCertificates []string `json:"allowed_certificates,omitempty"`
	AllowedTeams        []string `json:"allowed_teams"`
	Admin               bool     `json:"admin"`
}

func (s *Server) handleGetConfigAPIKeys(w http.ResponseWriter, r *http.Request) {
	allowedTeams := allowedTeamsFromContext(r.Context())

	s.mu.RLock()
	allKeys := s.cfg.AllAPIKeys()
	s.mu.RUnlock()

	var filtered []config.APIKeyConfig
	for _, key := range allKeys {
		if canManageKey(allowedTeams, key) {
			filtered = append(filtered, key)
		}
	}

	respondWithJSON(w, http.StatusOK, filtered)
}

func (s *Server) handlePostConfigAPIKeys(w http.ResponseWriter, r *http.Request) {
	payload, ok := decodeBody[config.APIKeyConfig](w, r)
	if !ok {
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())
	if len(allowedTeams) > 0 {
		if !isSubset(payload.AllowedTeams, allowedTeams) || !canManageKey(allowedTeams, payload) {
			respondWithError(w, http.StatusForbidden, "forbidden: cannot manage API keys with these scopes")
			return
		}
	}

	s.mu.RLock()
	validTeams := areTeamsValid(s.cfg, payload.AllowedTeams)
	s.mu.RUnlock()
	if !validTeams {
		respondWithError(w, http.StatusBadRequest, "one or more allowed_teams are invalid")
		return
	}

	validCerts, errStr := s.areCertificatesValidForTeams(payload.AllowedCertificates, payload.AllowedTeams, payload.Admin)
	if !validCerts {
		respondWithError(w, http.StatusBadRequest, errStr)
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
	s.cfg.State.APIKeys = append(s.cfg.State.APIKeys, payload)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	resp := APIKeyResponse{
		ID:                  payload.ID,
		Token:               payload.Token,
		CleartextToken:      cleartextToken,
		Description:         payload.Description,
		AllowedCertificates: payload.AllowedCertificates,
		AllowedTeams:        payload.AllowedTeams,
		Admin:               payload.Admin,
	}

	respondWithJSON(w, http.StatusCreated, resp)
}

func (s *Server) handlePutConfigAPIKeys(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.checkStatic(w, id, func() bool {
		_, is := findByID(s.cfg.APIKeys, id, func(k config.APIKeyConfig) string { return k.ID })
		return is
	}) {
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

	validCerts, errStr := s.areCertificatesValidForTeams(payload.AllowedCertificates, payload.AllowedTeams, payload.Admin)
	if !validCerts {
		respondWithError(w, http.StatusBadRequest, errStr)
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())

	getID := func(k config.APIKeyConfig) string { return k.ID }
	authCheck := func(existingKey config.APIKeyConfig) (bool, int, string) {
		if len(allowedTeams) > 0 {
			if !canManageKey(allowedTeams, existingKey) {
				return false, http.StatusNotFound, "API key configuration not found"
			}
			if !isSubset(payload.AllowedTeams, allowedTeams) || !canManageKey(allowedTeams, payload) {
				return false, http.StatusForbidden, "forbidden: cannot manage API keys with these scopes"
			}
		}
		return true, 0, ""
	}
	mutate := func(existing *config.APIKeyConfig) {
		existing.AllowedCertificates = payload.AllowedCertificates
		existing.AllowedTeams = payload.AllowedTeams
		existing.Admin = payload.Admin
		existing.Description = payload.Description
	}

	updateConfigResource(s, w, r, id, &s.cfg.State.APIKeys, getID, "API key configuration not found", authCheck, mutate)
}

func (s *Server) handleDeleteConfigAPIKeys(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.checkStatic(w, id, func() bool {
		_, is := findByID(s.cfg.APIKeys, id, func(k config.APIKeyConfig) string { return k.ID })
		return is
	}) {
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())
	getID := func(k config.APIKeyConfig) string { return k.ID }
	authCheck := func(existingKey config.APIKeyConfig) (bool, int, string) {
		if len(allowedTeams) > 0 {
			if !canManageKey(allowedTeams, existingKey) {
				return false, http.StatusNotFound, "API key configuration not found"
			}
		}
		return true, 0, ""
	}

	deleteConfigResource(s, w, r, id, &s.cfg.State.APIKeys, getID, "API key configuration not found", authCheck, nil)
}

func (s *Server) areCertificatesValidForTeams(allowedCerts, allowedTeams []string, isAdmin bool) (bool, string) {
	if len(allowedCerts) == 0 {
		return true, ""
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build a map of existing certificates and their team IDs
	allCerts := s.cfg.AllCertificates()
	certMap := make(map[string]string)
	for _, cert := range allCerts {
		certMap[cert.ID] = cert.TeamID
	}

	// Map for fast allowedTeams lookup
	teamMap := make(map[string]bool)
	for _, t := range allowedTeams {
		teamMap[t] = true
	}

	for _, id := range allowedCerts {
		teamID, exists := certMap[id]
		if !exists {
			return false, "certificate with ID " + id + " does not exist"
		}
		// If allowedTeams is non-empty, the certificate's team must match one of the allowed teams
		if len(allowedTeams) > 0 {
			if !teamMap[teamID] {
				return false, "certificate with ID " + id + " does not belong to any of the allowed teams"
			}
		}
	}
	return true, ""
}

