package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

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

	err = fetchEndpoint(ctx, client, baseURL+"/api/v1/certificates/status", token, &data.IssuedCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate status data: %w", err)
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
