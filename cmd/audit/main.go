package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"certer/internal/app/api"
	"certer/internal/app/config"
)

type AuditData struct {
	Teams        []config.TeamConfig          `json:"teams"`
	CertConfigs  []config.CertConfig          `json:"cert_configs"`
	APIKeys      []config.APIKeyConfig        `json:"api_keys"`
	IssuedCerts  []api.CertificateResponse    `json:"issued_certs"`
}

func main() {
	tokenFlag := flag.String("token", "", "Admin API Key token (falls back to AUDIT_TOKEN env var)")
	urlFlag := flag.String("url", "http://localhost:8080", "Target certer API URL (falls back to AUDIT_URL env var)")
	formatFlag := flag.String("format", "text", "Output report format: text (Markdown), json (falls back to AUDIT_FORMAT env var)")
	flag.Parse()

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("AUDIT_TOKEN")
	}
	url := *urlFlag
	if url == "" || url == "http://localhost:8080" {
		if envURL := os.Getenv("AUDIT_URL"); envURL != "" {
			url = envURL
		}
	}
	format := *formatFlag
	if format == "text" {
		if envFormat := os.Getenv("AUDIT_FORMAT"); envFormat != "" {
			format = envFormat
		}
	}

	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: Admin API token is required. Use -token flag or AUDIT_TOKEN environment variable.")
		os.Exit(1)
	}

	// Normalize target URL (ensure scheme and trim trailing slash)
	url = normalizeURL(url)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := &http.Client{}
	data, err := fetchAuditData(ctx, client, url, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching audit data: %v\n", err)
		os.Exit(1)
	}

	var output string
	switch format {
	case "json":
		output, err = formatJSON(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			os.Exit(1)
		}
	default:
		output = formatMarkdown(data)
	}

	fmt.Println(output)
}

func fetchAuditData(ctx context.Context, client *http.Client, baseURL, token string) (*AuditData, error) {
	data := &AuditData{}

	err := fetchEndpoint(ctx, client, baseURL+"/api/v1/config/teams", token, &data.Teams)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch teams: %w", err)
	}

	err = fetchEndpoint(ctx, client, baseURL+"/api/v1/config/certificates", token, &data.CertConfigs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates configuration: %w", err)
	}

	err = fetchEndpoint(ctx, client, baseURL+"/api/v1/config/api_keys", token, &data.APIKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch API keys configuration: %w", err)
	}

	err = fetchEndpoint(ctx, client, baseURL+"/api/v1/certificates", token, &data.IssuedCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issued certificates data: %w", err)
	}

	return data, nil
}

func fetchEndpoint(ctx context.Context, client *http.Client, url, token string, target interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

func formatMarkdown(data *AuditData) string {
	var sb strings.Builder
	sb.WriteString("# Certer System Audit Report\n\n")

	sb.WriteString("## 1. Teams\n")
	sb.WriteString("| ID | Name | Description |\n")
	sb.WriteString("|---|---|---|\n")
	for _, t := range data.Teams {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", t.ID, t.Name, t.Description))
	}
	sb.WriteString("\n")

	sb.WriteString("## 2. Certificate Configurations\n")
	sb.WriteString("| ID | Primary Domain | SANs | Team | Description | DNS Provider | Issued? |\n")
	sb.WriteString("|---|---|---|---|---|---|---|\n")

	issuedMap := make(map[string]bool)
	for _, ic := range data.IssuedCerts {
		issuedMap[ic.ID] = ic.Issued
	}

	for _, c := range data.CertConfigs {
		sans := strings.Join(c.Sans, ", ")
		issuedStr := "No"
		if issuedMap[c.ID] {
			issuedStr = "Yes"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
			c.ID, c.Primary, sans, c.TeamID, c.Description, c.DNSProvider, issuedStr))
	}
	sb.WriteString("\n")

	sb.WriteString("## 3. API Keys\n")
	sb.WriteString("| ID | Description | Admin? | Scoped Teams | Scoped Certificates |\n")
	sb.WriteString("|---|---|---|---|---|\n")
	for _, k := range data.APIKeys {
		adminStr := "No"
		if k.Admin {
			adminStr = "Yes"
		}
		teams := strings.Join(k.AllowedTeams, ", ")
		if len(k.AllowedTeams) == 0 {
			teams = "*"
		}
		certs := strings.Join(k.AllowedCertificates, ", ")
		if len(k.AllowedCertificates) == 0 {
			certs = "*"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", k.ID, k.Description, adminStr, teams, certs))
	}

	return sb.String()
}

func formatJSON(data *AuditData) (string, error) {
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func normalizeURL(url string) string {
	if url == "" {
		return ""
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	return strings.TrimSuffix(url, "/")
}

