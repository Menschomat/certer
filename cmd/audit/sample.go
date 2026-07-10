package main

import (
	"certer/internal/app/api"
	"certer/internal/app/config"
)

func sampleAuditData() *AuditData {
	return &AuditData{
		Teams: []config.TeamConfig{
			{ID: "platform", Name: "Platform", Description: "Owns ingress, edge routing, and shared infrastructure."},
			{ID: "payments", Name: "Payments", Description: "Maintains customer-facing payment services."},
			{ID: "research", Name: "Research", Description: "Sandbox and internal experimentation systems."},
		},
		CertConfigs: []config.CertConfig{
			{
				ID:          "prod-edge",
				Primary:     "app.example.com",
				Sans:        []string{"www.example.com", "api.example.com"},
				TeamID:      "platform",
				Description: "Primary production edge certificate.",
				DNSProvider: "cloudflare",
			},
			{
				ID:          "payments-api",
				Primary:     "payments.example.com",
				Sans:        []string{"checkout.example.com"},
				TeamID:      "payments",
				Description: "Payment API and checkout certificate.",
				DNSProvider: "route53",
			},
			{
				ID:          "legacy-admin",
				Primary:     "admin.legacy.example.com",
				TeamID:      "platform",
				Description: "Legacy admin console certificate that needs rotation.",
				DNSProvider: "hetzner",
			},
			{
				ID:          "lab-wildcard",
				Primary:     "*.lab.example.com",
				Sans:        []string{"lab.example.com"},
				TeamID:      "research",
				Description: "Unissued lab wildcard certificate.",
				DNSProvider: "cloudflare",
			},
		},
		APIKeys: []config.APIKeyConfig{
			{
				ID:                  "admin-ops",
				Description:         "Operations admin automation",
				Admin:               true,
				AllowedTeams:        []string{},
				AllowedCertificates: []string{},
			},
			{
				ID:                  "payments-deploy",
				Description:         "Payments deployment key",
				AllowedTeams:        []string{"payments"},
				AllowedCertificates: []string{"payments-api"},
			},
			{
				ID:                  "lab-reader",
				Description:         "Research status reader",
				AllowedTeams:        []string{"research"},
				AllowedCertificates: []string{"lab-wildcard"},
			},
		},
		IssuedCerts: []api.CertificateStatusResponse{
			{
				ID:            "prod-edge",
				Domain:        "app.example.com",
				Sans:          []string{"www.example.com", "api.example.com"},
				Issued:        true,
				Status:        "ok",
				Reason:        "certificate is valid",
				ExpiresAt:     "2026-11-15T08:00:00Z",
				DaysRemaining: intPtr(128),
				IsValid:       true,
			},
			{
				ID:            "payments-api",
				Domain:        "payments.example.com",
				Sans:          []string{"checkout.example.com"},
				Issued:        true,
				Status:        "warning",
				Reason:        "certificate is expiring soon",
				ExpiresAt:     "2026-07-28T08:00:00Z",
				DaysRemaining: intPtr(18),
				IsValid:       true,
			},
			{
				ID:            "legacy-admin",
				Domain:        "admin.legacy.example.com",
				Issued:        true,
				Status:        "critical",
				Reason:        "certificate has expired",
				ExpiresAt:     "2026-06-30T08:00:00Z",
				DaysRemaining: intPtr(-10),
				IsValid:       false,
			},
			{
				ID:      "lab-wildcard",
				Domain:  "*.lab.example.com",
				Issued:  false,
				Status:  "critical",
				Reason:  "certificate file missing or unreadable",
				IsValid: false,
			},
		},
	}
}

func intPtr(value int) *int {
	return &value
}
