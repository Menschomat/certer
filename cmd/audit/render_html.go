package main

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"
	"time"

	"certer/internal/app/api"
	"certer/internal/app/config"
)

type htmlReportView struct {
	GeneratedAt  string
	TargetURL    string
	Summary      htmlSummary
	Certificates []htmlCertificateRow
	Teams        []config.TeamConfig
	APIKeys      []htmlAPIKeyRow
}

type htmlSummary struct {
	TotalCertificates int
	OK                int
	Warning           int
	Critical          int
	Unissued          int
	Teams             int
	APIKeys           int
}

type htmlCertificateRow struct {
	ID            string
	Primary       string
	Sans          string
	TeamID        string
	Description   string
	DNSProvider   string
	Issued        string
	Status        string
	StatusLabel   string
	ExpiresAt     string
	DaysRemaining string
	Reason        string
}

type htmlAPIKeyRow struct {
	ID                  string
	Description         string
	Admin               string
	AllowedTeams        string
	AllowedCertificates string
}

//go:embed templates/report.html
var htmlReportTemplate string

func formatHTML(data *AuditData, meta ReportMeta) (string, error) {
	tmpl, err := template.New("report").Parse(htmlReportTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, buildHTMLReportView(data, meta)); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func buildHTMLReportView(data *AuditData, meta ReportMeta) htmlReportView {
	statusByID := make(map[string]api.CertificateStatusResponse, len(data.IssuedCerts))
	for _, status := range data.IssuedCerts {
		statusByID[status.ID] = status
	}

	view := htmlReportView{
		GeneratedAt: meta.GeneratedAt.UTC().Format(time.RFC3339),
		TargetURL:   meta.TargetURL,
		Teams:       data.Teams,
		Summary: htmlSummary{
			TotalCertificates: len(data.CertConfigs),
			Teams:             len(data.Teams),
			APIKeys:           len(data.APIKeys),
		},
	}

	for _, certConfig := range data.CertConfigs {
		status, ok := statusByID[certConfig.ID]
		row := buildHTMLCertificateRow(certConfig, status, ok)
		view.Certificates = append(view.Certificates, row)

		switch row.Status {
		case "ok":
			view.Summary.OK++
		case "warning":
			view.Summary.Warning++
		default:
			view.Summary.Critical++
		}
		if row.Issued == "No" {
			view.Summary.Unissued++
		}
	}

	for _, key := range data.APIKeys {
		admin := "No"
		if key.Admin {
			admin = "Yes"
		}
		view.APIKeys = append(view.APIKeys, htmlAPIKeyRow{
			ID:                  key.ID,
			Description:         key.Description,
			Admin:               admin,
			AllowedTeams:        displayList(key.AllowedTeams),
			AllowedCertificates: displayList(key.AllowedCertificates),
		})
	}

	return view
}

func buildHTMLCertificateRow(certConfig config.CertConfig, status api.CertificateStatusResponse, hasStatus bool) htmlCertificateRow {
	statusValue := status.Status
	if statusValue == "" {
		statusValue = "critical"
	}
	reason := status.Reason
	if !hasStatus {
		reason = "status unavailable"
	}

	issued := "No"
	if status.Issued {
		issued = "Yes"
	}

	return htmlCertificateRow{
		ID:            certConfig.ID,
		Primary:       certConfig.Primary,
		Sans:          displayList(certConfig.Sans),
		TeamID:        certConfig.TeamID,
		Description:   certConfig.Description,
		DNSProvider:   displayValue(certConfig.DNSProvider),
		Issued:        issued,
		Status:        statusValue,
		StatusLabel:   strings.ToUpper(statusValue[:1]) + statusValue[1:],
		ExpiresAt:     displayValue(status.ExpiresAt),
		DaysRemaining: displayDaysRemaining(status.DaysRemaining),
		Reason:        displayValue(reason),
	}
}
