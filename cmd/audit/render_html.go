package main

import (
	"bytes"
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

const htmlReportTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Certer System Report</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f8fb;
      --panel: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --line: #d9e0ea;
      --ok: #0f766e;
      --ok-bg: #dff7ef;
      --warning: #a15c07;
      --warning-bg: #fff2cc;
      --critical: #b42318;
      --critical-bg: #ffe4e0;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }
    main {
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 32px 0 48px;
    }
    header {
      margin-bottom: 24px;
    }
    h1 {
      margin: 0;
      font-size: 32px;
      line-height: 1.15;
      letter-spacing: 0;
    }
    h2 {
      margin: 0 0 12px;
      font-size: 20px;
      letter-spacing: 0;
    }
    .meta {
      margin-top: 8px;
      color: var(--muted);
      font-size: 14px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(138px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .metric, section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .metric {
      padding: 14px 16px;
    }
    .metric .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .metric .value {
      margin-top: 6px;
      font-size: 28px;
      font-weight: 700;
    }
    section {
      margin-top: 16px;
      overflow: hidden;
    }
    .section-head {
      padding: 18px 20px 10px;
    }
    .table-wrap {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th, td {
      padding: 10px 12px;
      border-top: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .04em;
      background: #f9fbfd;
    }
    td.wrap {
      white-space: normal;
      min-width: 180px;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
    }
    .status {
      display: inline-block;
      min-width: 72px;
      border-radius: 999px;
      padding: 3px 9px;
      font-size: 12px;
      font-weight: 700;
      text-align: center;
    }
    .status-ok { color: var(--ok); background: var(--ok-bg); }
    .status-warning { color: var(--warning); background: var(--warning-bg); }
    .status-critical { color: var(--critical); background: var(--critical-bg); }
    footer {
      margin-top: 18px;
      color: var(--muted);
      font-size: 13px;
    }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Certer System Report</h1>
      <div class="meta">Target: {{.TargetURL}} · Generated: {{.GeneratedAt}} · generated by certer audit</div>
    </header>

    <div class="summary" aria-label="Summary">
      <div class="metric"><div class="label">Total Certificates</div><div class="value">{{.Summary.TotalCertificates}}</div></div>
      <div class="metric"><div class="label">OK</div><div class="value">{{.Summary.OK}}</div></div>
      <div class="metric"><div class="label">Warning</div><div class="value">{{.Summary.Warning}}</div></div>
      <div class="metric"><div class="label">Critical</div><div class="value">{{.Summary.Critical}}</div></div>
      <div class="metric"><div class="label">Unissued</div><div class="value">{{.Summary.Unissued}}</div></div>
      <div class="metric"><div class="label">Teams</div><div class="value">{{.Summary.Teams}}</div></div>
      <div class="metric"><div class="label">API Keys</div><div class="value">{{.Summary.APIKeys}}</div></div>
    </div>

    <section>
      <div class="section-head"><h2>Certificates</h2></div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Primary Domain</th>
              <th>SANs</th>
              <th>Team</th>
              <th>DNS Provider</th>
              <th>Issued</th>
              <th>Expires</th>
              <th>Days Remaining</th>
              <th>Reason</th>
              <th>Description</th>
              <th>ID</th>
            </tr>
          </thead>
          <tbody>
            {{range .Certificates}}
            <tr>
              <td><span class="status status-{{.Status}}">{{.StatusLabel}}</span></td>
              <td>{{.Primary}}</td>
              <td class="wrap">{{.Sans}}</td>
              <td><code>{{.TeamID}}</code></td>
              <td>{{.DNSProvider}}</td>
              <td>{{.Issued}}</td>
              <td>{{.ExpiresAt}}</td>
              <td>{{.DaysRemaining}}</td>
              <td class="wrap">{{.Reason}}</td>
              <td class="wrap">{{.Description}}</td>
              <td><code>{{.ID}}</code></td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>

    <section>
      <div class="section-head"><h2>Teams</h2></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>ID</th><th>Description</th></tr></thead>
          <tbody>
            {{range .Teams}}
            <tr><td>{{.Name}}</td><td><code>{{.ID}}</code></td><td class="wrap">{{.Description}}</td></tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>

    <section>
      <div class="section-head"><h2>API Keys</h2></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Description</th><th>Admin</th><th>Scoped Teams</th><th>Scoped Certificates</th><th>ID</th></tr></thead>
          <tbody>
            {{range .APIKeys}}
            <tr>
              <td class="wrap">{{.Description}}</td>
              <td>{{.Admin}}</td>
              <td class="wrap">{{.AllowedTeams}}</td>
              <td class="wrap">{{.AllowedCertificates}}</td>
              <td><code>{{.ID}}</code></td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
    </section>

    <footer>Static report generated by certer audit.</footer>
  </main>
</body>
</html>
`
