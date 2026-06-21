package api

import (
	"net/http"
	"os"
	"path/filepath"

	"certer/internal/app/config"
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

	isAdmin := isAdminFromContext(r.Context())

	for _, cc := range certs {
		if cc.Primary == "" {
			continue
		}

		if !isAdmin {
			// Only return certificates for domains authorized by the token
			if !isDomainAllowed(cc.Primary, allowedDomains) {
				continue
			}

			// Only return certificates for teams authorized by the token
			if !isTeamAllowed(cc.TeamID, allowedTeams) {
				continue
			}
		} else {
			// Admin Token:
			// Scoped Admin is restricted to allowed teams. Root Admin (empty allowedTeams) has access to all.
			if len(allowedTeams) > 0 && !isTeamAllowed(cc.TeamID, allowedTeams) {
				continue
			}
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
	if s.checkStatic(w, id, func() bool {
		_, is := findByID(s.cfg.Certificates, id, func(c config.CertConfig) string { return c.ID })
		return is
	}) {
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

	getID := func(c config.CertConfig) string { return c.ID }
	authCheck := func(existingCert config.CertConfig) (bool, int, string) {
		if len(allowedTeams) > 0 {
			if !isTeamAllowed(existingCert.TeamID, allowedTeams) {
				return false, http.StatusNotFound, "certificate configuration not found"
			}
			if !isTeamAllowed(payload.TeamID, allowedTeams) {
				return false, http.StatusForbidden, "forbidden: cannot manage certificates for this team"
			}
		}
		return true, 0, ""
	}
	mutate := func(existing *config.CertConfig) {
		existing.Primary = payload.Primary
		existing.Sans = payload.Sans
		existing.TeamID = payload.TeamID
		existing.Description = payload.Description
		existing.DNSProvider = payload.DNSProvider
	}

	updateConfigResource(s, w, r, id, &s.cfg.State.Certificates, getID, "certificate configuration not found", authCheck, mutate)
}

func (s *Server) handleDeleteConfigCertificates(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.checkStatic(w, id, func() bool {
		_, is := findByID(s.cfg.Certificates, id, func(c config.CertConfig) string { return c.ID })
		return is
	}) {
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())
	getID := func(c config.CertConfig) string { return c.ID }
	authCheck := func(existingCert config.CertConfig) (bool, int, string) {
		if len(allowedTeams) > 0 {
			if !isTeamAllowed(existingCert.TeamID, allowedTeams) {
				return false, http.StatusNotFound, "certificate configuration not found"
			}
		}
		return true, 0, ""
	}

	deleteConfigResource(s, w, r, id, &s.cfg.State.Certificates, getID, "certificate configuration not found", authCheck, nil)
}

