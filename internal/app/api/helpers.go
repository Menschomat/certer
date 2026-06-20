package api

import (
	"context"
	"encoding/json"
	"net/http"

	"cert-central/internal/app/config"
)

type contextKey string

const allowedDomainsKey contextKey = "allowed_domains"
const allowedTeamsKey contextKey = "allowed_teams"
const isAdminKey contextKey = "is_admin"

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

func isAdminFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(isAdminKey).(bool); ok {
		return val
	}
	return false
}

func isTeamAllowed(teamID string, allowedTeams []string) bool {
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

func isSubset(sub, parent []string) bool {
	parentMap := make(map[string]bool)
	for _, p := range parent {
		parentMap[p] = true
	}
	for _, s := range sub {
		if !parentMap[s] {
			return false
		}
	}
	return true
}

func canManageKey(adminTeams []string, target config.APIKeyConfig) bool {
	// Root Admin can manage all keys
	if len(adminTeams) == 0 {
		return true
	}
	// Scoped Admin cannot manage Root Admin keys
	if target.Admin && len(target.AllowedTeams) == 0 {
		return false
	}
	// Scoped Admin can only manage keys scoped to a subset of their allowed teams
	return isSubset(target.AllowedTeams, adminTeams)
}

func isValidTeam(cfg *config.Config, teamID string) bool {
	if teamID == "" {
		return false
	}
	for _, t := range cfg.AllTeams() {
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
