package main

import (
	"fmt"
	"strings"
)

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
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			k.ID, k.Description, adminStr, displayList(k.AllowedTeams), displayList(k.AllowedCertificates)))
	}

	return sb.String()
}
