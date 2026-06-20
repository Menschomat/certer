package api

import (
	"net/http"
	"os"
	"path/filepath"

	"cert-central/internal/app/config"
)

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

func (s *Server) handleGetCertificates(w http.ResponseWriter, r *http.Request) {
	allowedDomains := allowedDomainsFromContext(r.Context())
	allowedTeams := allowedTeamsFromContext(r.Context())

	respList := []CertificateResponse{}

	s.mu.RLock()
	allCerts := s.cfg.AllCertificates()
	certs := make([]config.CertConfig, len(allCerts))
	copy(certs, allCerts)
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

func (s *Server) handleGetConfigCertificates(w http.ResponseWriter, r *http.Request) {
	allowedTeams := allowedTeamsFromContext(r.Context())

	s.mu.RLock()
	allCerts := s.cfg.AllCertificates()
	s.mu.RUnlock()

	var filtered []config.CertConfig
	for _, cert := range allCerts {
		if len(allowedTeams) > 0 {
			if isTeamAllowed(cert.TeamID, allowedTeams) {
				filtered = append(filtered, cert)
			}
		} else {
			filtered = append(filtered, cert)
		}
	}

	respondWithJSON(w, http.StatusOK, filtered)
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
	if payload.TeamID == "" {
		payload.TeamID = "system"
	}

	allowedTeams := allowedTeamsFromContext(r.Context())
	if len(allowedTeams) > 0 {
		if !isTeamAllowed(payload.TeamID, allowedTeams) {
			respondWithError(w, http.StatusForbidden, "forbidden: cannot manage certificates for this team")
			return
		}
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
	s.cfg.State.Certificates = append(s.cfg.State.Certificates, payload)
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

	s.mu.RLock()
	_, isStatic := findByID(s.cfg.Certificates, id, func(c config.CertConfig) string { return c.ID })
	s.mu.RUnlock()
	if isStatic {
		respondWithError(w, http.StatusBadRequest, "cannot modify or delete statically configured resources via the API")
		return
	}

	payload, ok := decodeBody[config.CertConfig](w, r)
	if !ok {
		return
	}
	if payload.TeamID == "" {
		payload.TeamID = "system"
	}

	s.mu.RLock()
	validTeam := isValidTeam(s.cfg, payload.TeamID)
	s.mu.RUnlock()
	if !validTeam {
		respondWithError(w, http.StatusBadRequest, "invalid or missing team_id")
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.State.Certificates, id, func(c config.CertConfig) string { return c.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "certificate configuration not found")
		return
	}

	existingCert := s.cfg.State.Certificates[foundIdx]

	if len(allowedTeams) > 0 {
		if !isTeamAllowed(existingCert.TeamID, allowedTeams) {
			s.mu.Unlock()
			respondWithError(w, http.StatusNotFound, "certificate configuration not found")
			return
		}
		if !isTeamAllowed(payload.TeamID, allowedTeams) {
			s.mu.Unlock()
			respondWithError(w, http.StatusForbidden, "forbidden: cannot manage certificates for this team")
			return
		}
	}

	s.cfg.State.Certificates[foundIdx].Primary = payload.Primary
	s.cfg.State.Certificates[foundIdx].Sans = payload.Sans
	s.cfg.State.Certificates[foundIdx].TeamID = payload.TeamID
	s.cfg.State.Certificates[foundIdx].Description = payload.Description
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

	s.mu.RLock()
	_, isStatic := findByID(s.cfg.Certificates, id, func(c config.CertConfig) string { return c.ID })
	s.mu.RUnlock()
	if isStatic {
		respondWithError(w, http.StatusBadRequest, "cannot modify or delete statically configured resources via the API")
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())

	s.mu.Lock()
	foundIdx, found := findByID(s.cfg.State.Certificates, id, func(c config.CertConfig) string { return c.ID })
	if !found {
		s.mu.Unlock()
		respondWithError(w, http.StatusNotFound, "certificate configuration not found")
		return
	}

	existingCert := s.cfg.State.Certificates[foundIdx]

	if len(allowedTeams) > 0 {
		if !isTeamAllowed(existingCert.TeamID, allowedTeams) {
			s.mu.Unlock()
			respondWithError(w, http.StatusNotFound, "certificate configuration not found")
			return
		}
	}

	s.cfg.State.Certificates = removeAtIndex(s.cfg.State.Certificates, foundIdx)
	s.mu.Unlock()

	if err := s.saveAndReload(r.Context()); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
