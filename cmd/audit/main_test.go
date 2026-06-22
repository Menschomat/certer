package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"certer/internal/app/api"
	"certer/internal/app/config"
)

func TestFormatMarkdown(t *testing.T) {
	data := &AuditData{
		Teams: []config.TeamConfig{
			{ID: "system", Name: "System", Description: "System Team"},
			{ID: "team-1", Name: "Dev Team", Description: "Devs"},
		},
		CertConfigs: []config.CertConfig{
			{ID: "cert-1", Primary: "example.com", Sans: []string{"*.example.com"}, TeamID: "team-1", Description: "Test Cert", DNSProvider: "hetzner"},
		},
		APIKeys: []config.APIKeyConfig{
			{ID: "key-1", Description: "Key 1", AllowedCertificates: []string{"cert-1"}, AllowedTeams: []string{"team-1"}, Admin: false},
		},
		IssuedCerts: []api.CertificateResponse{
			{ID: "cert-1", Domain: "example.com", Sans: []string{"*.example.com"}, Issued: true},
		},
	}

	markdown := formatMarkdown(data)

	// Check if key headers and tables exist
	if !strings.Contains(markdown, "# Certer System Audit Report") {
		t.Errorf("Expected Markdown to contain report title")
	}
	if !strings.Contains(markdown, "## 1. Teams") {
		t.Errorf("Expected Markdown to contain Teams section")
	}
	if !strings.Contains(markdown, "system | System | System Team") {
		t.Errorf("Expected Markdown to contain system team entry")
	}
	if !strings.Contains(markdown, "cert-1 | example.com | *.example.com | team-1 | Test Cert | hetzner | Yes") {
		t.Errorf("Expected Markdown to contain certificate configuration table entry with issuance status")
	}
	if !strings.Contains(markdown, "key-1 | Key 1 | No | team-1 | cert-1") {
		t.Errorf("Expected Markdown to contain API key table entry")
	}
}

func TestFormatJSON(t *testing.T) {
	data := &AuditData{
		Teams: []config.TeamConfig{
			{ID: "team-1", Name: "Dev Team"},
		},
	}

	jsonData, err := formatJSON(data)
	if err != nil {
		t.Fatalf("formatJSON failed: %v", err)
	}

	var parsed AuditData
	if err := json.Unmarshal([]byte(jsonData), &parsed); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if len(parsed.Teams) != 1 || parsed.Teams[0].Name != "Dev Team" {
		t.Errorf("Expected team 'Dev Team' inside parsed JSON, got: %+v", parsed.Teams)
	}
}

func TestFetchAuditData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-admin-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1/config/teams":
			_ = json.NewEncoder(w).Encode([]config.TeamConfig{{ID: "team-1", Name: "Team 1"}})
		case "/api/v1/config/certificates":
			_ = json.NewEncoder(w).Encode([]config.CertConfig{{ID: "cert-1", Primary: "example.com"}})
		case "/api/v1/config/api_keys":
			_ = json.NewEncoder(w).Encode([]config.APIKeyConfig{{ID: "key-1", Description: "Key 1"}})
		case "/api/v1/certificates":
			_ = json.NewEncoder(w).Encode([]api.CertificateResponse{{ID: "cert-1", Domain: "example.com", Issued: true}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	ctx := context.Background()
	client := &http.Client{}

	t.Run("Success", func(t *testing.T) {
		data, err := fetchAuditData(ctx, client, ts.URL, "test-admin-token")
		if err != nil {
			t.Fatalf("fetchAuditData failed: %v", err)
		}

		if len(data.Teams) != 1 || data.Teams[0].ID != "team-1" {
			t.Errorf("Unexpected teams output: %+v", data.Teams)
		}
		if len(data.CertConfigs) != 1 || data.CertConfigs[0].ID != "cert-1" {
			t.Errorf("Unexpected cert configs output: %+v", data.CertConfigs)
		}
		if len(data.APIKeys) != 1 || data.APIKeys[0].ID != "key-1" {
			t.Errorf("Unexpected api keys output: %+v", data.APIKeys)
		}
		if len(data.IssuedCerts) != 1 || data.IssuedCerts[0].ID != "cert-1" || !data.IssuedCerts[0].Issued {
			t.Errorf("Unexpected issued certs output: %+v", data.IssuedCerts)
		}
	})

	t.Run("Unauthorized", func(t *testing.T) {
		_, err := fetchAuditData(ctx, client, ts.URL, "bad-token")
		if err == nil {
			t.Fatal("Expected fetch to fail on unauthorized status, but succeeded")
		}
	})
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"http://localhost:8080", "http://localhost:8080"},
		{"https://certer.menscho.space/", "https://certer.menscho.space"},
		{"certer.menscho.space", "http://certer.menscho.space"},
		{"certer.menscho.space/", "http://certer.menscho.space"},
		{"http://127.0.0.1/", "http://127.0.0.1"},
	}

	for _, tc := range tests {
		got := normalizeURL(tc.input)
		if got != tc.expected {
			t.Errorf("normalizeURL(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}
}

