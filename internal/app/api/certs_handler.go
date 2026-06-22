package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
	allowedCertificates := allowedCertificatesFromContext(r.Context())
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

		if allowed, _ := checkCertAccess(isAdmin, cc.ID, cc.TeamID, allowedCertificates, allowedTeams); !allowed {
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
			if contains(allowedTeams, cert.TeamID) {
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
		payload.TeamID = defaultTeamID
	}

	allowedTeams := allowedTeamsFromContext(r.Context())
	if len(allowedTeams) > 0 {
		if !contains(allowedTeams, payload.TeamID) {
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
	if err := s.saveAndReloadLocked(r.Context()); err != nil {
		s.mu.Unlock()
		respondWithError(w, http.StatusInternalServerError, "failed to persist configuration changes")
		return
	}
	s.mu.Unlock()

	respondWithJSON(w, http.StatusCreated, payload)
}

func (s *Server) handlePutConfigCertificates(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.checkStatic(w, id, func() bool {
		_, is := findByID(s.cfg.Certificates, id, getCertConfigID)
		return is
	}) {
		return
	}

	payload, ok := decodeBody[config.CertConfig](w, r)
	if !ok {
		return
	}
	if payload.TeamID == "" {
		payload.TeamID = defaultTeamID
	}

	s.mu.RLock()
	validTeam := isValidTeam(s.cfg, payload.TeamID)
	s.mu.RUnlock()
	if !validTeam {
		respondWithError(w, http.StatusBadRequest, "invalid or missing team_id")
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())

	authCheck := func(existingCert config.CertConfig) (bool, int, string) {
		if len(allowedTeams) > 0 {
			if !contains(allowedTeams, existingCert.TeamID) {
				return false, http.StatusNotFound, "certificate configuration not found"
			}
			if !contains(allowedTeams, payload.TeamID) {
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

	updateConfigResource(s, w, r, id, &s.cfg.State.Certificates, getCertConfigID, "certificate configuration not found", authCheck, mutate)
}

func (s *Server) handleDeleteConfigCertificates(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.checkStatic(w, id, func() bool {
		_, is := findByID(s.cfg.Certificates, id, getCertConfigID)
		return is
	}) {
		return
	}

	allowedTeams := allowedTeamsFromContext(r.Context())
	authCheck := func(existingCert config.CertConfig) (bool, int, string) {
		if len(allowedTeams) > 0 {
			if !contains(allowedTeams, existingCert.TeamID) {
				return false, http.StatusNotFound, "certificate configuration not found"
			}
		}
		return true, 0, ""
	}

	deleteConfigResource(s, w, r, id, &s.cfg.State.Certificates, getCertConfigID, "certificate configuration not found", authCheck, nil)
}

func (s *Server) handleGetCertificateRaw(w http.ResponseWriter, r *http.Request) {
	s.handleGetRawFile(w, r, false)
}

func (s *Server) handleGetPrivateKeyRaw(w http.ResponseWriter, r *http.Request) {
	s.handleGetRawFile(w, r, true)
}

func (s *Server) handleGetRawFile(w http.ResponseWriter, r *http.Request, getPrivateKey bool) {
	identifier := r.PathValue("identifier")
	if identifier == "" {
		respondWithError(w, http.StatusBadRequest, "missing identifier")
		return
	}

	allowedCertificates := allowedCertificatesFromContext(r.Context())
	allowedTeams := allowedTeamsFromContext(r.Context())
	isAdmin := isAdminFromContext(r.Context())

	s.mu.RLock()
	allCerts := s.cfg.AllCertificates()
	s.mu.RUnlock()

	cc := s.findCertificateByIdentifier(identifier, allCerts)
	if cc == nil {
		respondWithError(w, http.StatusNotFound, "certificate configuration not found")
		return
	}

	// Scoping / Authorization check
	if allowed, msg := checkCertAccess(isAdmin, cc.ID, cc.TeamID, allowedCertificates, allowedTeams); !allowed {
		respondWithError(w, http.StatusForbidden, msg)
		return
	}

	var filePath string
	if getPrivateKey {
		filePath = filepath.Join(s.storageDir, cc.ID+".key")
	} else {
		filePath = filepath.Join(s.storageDir, cc.ID+".crt")
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			respondWithError(w, http.StatusNotFound, "certificate not yet issued")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to read certificate file")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) findCertificateByIdentifier(identifier string, certs []config.CertConfig) *config.CertConfig {
	var bestMatch *config.CertConfig
	var bestMatchIsPrimary bool

	for i := range certs {
		cc := &certs[i]

		// 1. Exact ID Match (Highest Priority)
		if cc.ID == identifier {
			return cc
		}

		// 2. Primary Domain Match
		if cc.Primary == identifier {
			// Tie-breaker: If we already have a primary match, take the newer one (larger UUIDv7 ID)
			if bestMatch == nil || !bestMatchIsPrimary || cc.ID > bestMatch.ID {
				bestMatch = cc
				bestMatchIsPrimary = true
			}
			continue
		}

		// 3. SAN Match (Only if we haven't found a primary domain match yet)
		if !bestMatchIsPrimary {
			for _, san := range cc.Sans {
				if san == identifier || matchesWildcard(san, identifier) {
					// Tie-breaker: If we already have a SAN match, take the newer one (larger UUIDv7)
					if bestMatch == nil || cc.ID > bestMatch.ID {
						bestMatch = cc
					}
					break
				}
			}
		}
	}
	return bestMatch
}

func matchesWildcard(pattern, domain string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // e.g. ".example.com"
	return strings.HasSuffix(domain, suffix) && strings.Count(domain, ".") == strings.Count(pattern, ".")
}


