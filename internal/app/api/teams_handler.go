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
	if s.checkStatic(w, id, func() bool {
		if id == "system" {
			return true
		}
		_, is := findByID(s.cfg.Teams, id, func(t config.TeamConfig) string { return t.ID })
		return is
	}) {
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())
	if len(allowedTeams) > 0 {
		respondWithError(w, http.StatusForbidden, "forbidden: only root admins can manage team configurations")
		return
	}

	payload, ok := decodeBody[config.TeamConfig](w, r)
	if !ok {
		return
	}

	getID := func(t config.TeamConfig) string { return t.ID }
	mutate := func(existing *config.TeamConfig) {
		existing.Name = payload.Name
		existing.Description = payload.Description
	}

	updateConfigResource(s, w, r, id, &s.cfg.State.Teams, getID, "team configuration not found", nil, mutate)
}

func (s *Server) handleDeleteConfigTeams(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.checkStatic(w, id, func() bool {
		if id == "system" {
			return true
		}
		_, is := findByID(s.cfg.Teams, id, func(t config.TeamConfig) string { return t.ID })
		return is
	}) {
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())
	if len(allowedTeams) > 0 {
		respondWithError(w, http.StatusForbidden, "forbidden: only root admins can manage team configurations")
		return
	}

	getID := func(t config.TeamConfig) string { return t.ID }
	preDeleteCheck := func(existing config.TeamConfig) (bool, int, string) {
		// Held under s.mu.Lock() in deleteConfigResource
		for _, cert := range s.cfg.AllCertificates() {
			if cert.TeamID == id {
				return false, http.StatusBadRequest, "cannot delete team that is in use by certificates"
			}
		}
		for _, key := range s.cfg.AllAPIKeys() {
			for _, allowedTeam := range key.AllowedTeams {
				if allowedTeam == id {
					return false, http.StatusBadRequest, "cannot delete team that is in use by API keys"
				}
			}
		}
		return true, 0, ""
	}

	deleteConfigResource(s, w, r, id, &s.cfg.State.Teams, getID, "team configuration not found", nil, preDeleteCheck)
}

