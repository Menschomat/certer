package main

import (
	"fmt"
	"strings"
	"time"

	"certer/internal/app/api"
	"certer/internal/app/config"
)

type AuditData struct {
	Teams       []config.TeamConfig             `json:"teams"`
	CertConfigs []config.CertConfig             `json:"cert_configs"`
	APIKeys     []config.APIKeyConfig           `json:"api_keys"`
	IssuedCerts []api.CertificateStatusResponse `json:"issued_certs"`
}

type ReportMeta struct {
	GeneratedAt time.Time
	TargetURL   string
}

func renderAuditReport(data *AuditData, format string, meta ReportMeta) (string, error) {
	switch format {
	case "text":
		return formatMarkdown(data), nil
	case "json":
		return formatJSON(data)
	case "html":
		return formatHTML(data, meta)
	default:
		return "", fmt.Errorf("unsupported output format %q", format)
	}
}

func isSupportedFormat(format string) bool {
	switch format {
	case "text", "json", "html":
		return true
	default:
		return false
	}
}

func displayList(values []string) string {
	if len(values) == 0 {
		return "*"
	}
	return strings.Join(values, ", ")
}

func displayValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func displayDaysRemaining(days *int) string {
	if days == nil {
		return "-"
	}
	if *days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", *days)
}
