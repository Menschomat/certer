package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"certer/internal/app/config"
)

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
		existing.AllowedDomains = payload.AllowedDomains
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

