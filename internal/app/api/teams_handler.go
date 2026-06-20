package api

import (
	"net/http"

	"cert-central/internal/app/config"
)

func (s *Server) handleGetConfigTeams(w http.ResponseWriter, r *http.Request) {
	allowedTeams := allowedTeamsFromContext(r.Context())

	s.mu.RLock()
	allTeams := s.cfg.AllTeams()
	s.mu.RUnlock()

	var filtered []config.TeamConfig
	for _, team := range allTeams {
		if len(allowedTeams) > 0 {
			if team.ID == "system" || isTeamAllowed(team.ID, allowedTeams) {
				filtered = append(filtered, team)
			}
		} else {
			filtered = append(filtered, team)
		}
	}

	respondWithJSON(w, http.StatusOK, filtered)
}

func (s *Server) handlePostConfigTeams(w http.ResponseWriter, r *http.Request) {
	allowedTeams := allowedTeamsFromContext(r.Context())
	if len(allowedTeams) > 0 {
		respondWithError(w, http.StatusForbidden, "forbidden: only root admins can manage team configurations")
		return
	}

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
	s.cfg.State.Teams = append(s.cfg.State.Teams, payload)
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

	allowedTeams := allowedTeamsFromContext(r.Context())
	if len(allowedTeams) > 0 {
		respondWithError(w, http.StatusForbidden, "forbidden: only root admins can manage team configurations")
		return
	}

	if id == "system" {
		respondWithError(w, http.StatusBadRequest, "cannot modify or delete statically configured resources via the API")
		return
	}
	s.mu.RLock()
	_, isStatic := findByID(s.cfg.Teams, id, func(t config.TeamConfig) string { return t.ID })
	s.mu.RUnlock()
	if isStatic {
		respondWithError(w, http.StatusBadRequest, "cannot modify or delete statically configured resources via the API")
		return
	}

	payload, ok := decodeBody[config.TeamConfig](w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.State.Teams, id, func(t config.TeamConfig) string { return t.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "team configuration not found")
		return
	}

	s.cfg.State.Teams[foundIdx].Name = payload.Name
	s.cfg.State.Teams[foundIdx].Description = payload.Description
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

	allowedTeams := allowedTeamsFromContext(r.Context())
	if len(allowedTeams) > 0 {
		respondWithError(w, http.StatusForbidden, "forbidden: only root admins can manage team configurations")
		return
	}

	if id == "system" {
		respondWithError(w, http.StatusBadRequest, "cannot modify or delete statically configured resources via the API")
		return
	}
	s.mu.RLock()
	_, isStatic := findByID(s.cfg.Teams, id, func(t config.TeamConfig) string { return t.ID })
	s.mu.RUnlock()
	if isStatic {
		respondWithError(w, http.StatusBadRequest, "cannot modify or delete statically configured resources via the API")
		return
	}

	s.mu.RLock()
	allCerts := s.cfg.AllCertificates()
	allKeys := s.cfg.AllAPIKeys()
	s.mu.RUnlock()

	for _, cert := range allCerts {
		if cert.TeamID == id {
			respondWithError(w, http.StatusBadRequest, "cannot delete team that is in use by certificates")
			return
		}
	}
	for _, key := range allKeys {
		for _, allowedTeam := range key.AllowedTeams {
			if allowedTeam == id {
				respondWithError(w, http.StatusBadRequest, "cannot delete team that is in use by API keys")
				return
			}
		}
	}

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.State.Teams, id, func(t config.TeamConfig) string { return t.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "team configuration not found")
		return
	}

	s.cfg.State.Teams = removeAtIndex(s.cfg.State.Teams, foundIdx)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
