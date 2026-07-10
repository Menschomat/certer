package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type auditOptions struct {
	Token      string
	URL        string
	Format     string
	OutputPath string
}

func runAudit(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	opts, err := parseAuditOptions(args, stderr, getenv)
	if err != nil {
		if err != flag.ErrHelp {
			fmt.Fprintln(stderr, err)
		}
		return 2
	}

	if opts.Token == "" {
		fmt.Fprintln(stderr, "Error: Admin API token is required. Use -token flag or AUDIT_TOKEN environment variable.")
		return 1
	}
	if !isSupportedFormat(opts.Format) {
		fmt.Fprintf(stderr, "Error: unsupported output format %q. Use text, json, or html.\n", opts.Format)
		return 1
	}

	opts.URL = normalizeURL(opts.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	data, err := fetchAuditData(ctx, &http.Client{}, opts.URL, opts.Token)
	if err != nil {
		fmt.Fprintf(stderr, "Error fetching audit data: %v\n", err)
		return 1
	}

	output, err := renderAuditReport(data, opts.Format, ReportMeta{
		GeneratedAt: time.Now(),
		TargetURL:   opts.URL,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error formatting %s: %v\n", opts.Format, err)
		return 1
	}

	if opts.OutputPath != "" {
		if err := os.WriteFile(opts.OutputPath, []byte(output), 0644); err != nil {
			fmt.Fprintf(stderr, "Error writing output file: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintln(stdout, output)
	return 0
}

func parseAuditOptions(args []string, stderr io.Writer, getenv func(string) string) (auditOptions, error) {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	tokenFlag := fs.String("token", "", "Admin API Key token (falls back to AUDIT_TOKEN env var)")
	urlFlag := fs.String("url", "http://localhost:8080", "Target certer API URL (falls back to AUDIT_URL env var)")
	formatFlag := fs.String("format", "text", "Output report format: text (Markdown), json, html (falls back to AUDIT_FORMAT env var)")
	outputFlag := fs.String("output", "", "Write report to file path (falls back to AUDIT_OUTPUT env var)")

	if err := fs.Parse(args); err != nil {
		return auditOptions{}, err
	}

	opts := auditOptions{
		Token:      firstNonEmpty(*tokenFlag, getenv("AUDIT_TOKEN")),
		URL:        *urlFlag,
		Format:     *formatFlag,
		OutputPath: firstNonEmpty(*outputFlag, getenv("AUDIT_OUTPUT")),
	}

	if opts.URL == "" || opts.URL == "http://localhost:8080" {
		opts.URL = firstNonEmpty(getenv("AUDIT_URL"), opts.URL)
	}
	if opts.Format == "text" {
		opts.Format = firstNonEmpty(getenv("AUDIT_FORMAT"), opts.Format)
	}

	return opts, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
