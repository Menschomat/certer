package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	Address    string
	Token      string
	HTTPClient *http.Client
}

func NewClient(address, token string) *Client {
	return &Client{
		Address: address,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) sendRequest(ctx context.Context, method, path string, bodyVal interface{}, respVal interface{}) error {
	var bodyReader *bytes.Reader
	if bodyVal != nil {
		data, err := json.Marshal(bodyVal)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(data)
	}

	url := fmt.Sprintf("%s%s", c.Address, path)
	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return err
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if bodyVal != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			if msg, exists := errResp["error"]; exists {
				return fmt.Errorf("API error (status %d): %s", resp.StatusCode, msg)
			}
		}
		return fmt.Errorf("API error (status %d)", resp.StatusCode)
	}

	if respVal != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(respVal)
	}

	return nil
}

type CertConfig struct {
	Primary string   `json:"primary"`
	Sans    []string `json:"sans,omitempty"`
}

type APIKeyConfig struct {
	Token          string   `json:"token"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	Admin          bool     `json:"admin"`
}

type CertificateData struct {
	Domain       string   `json:"domain"`
	Sans         []string `json:"sans"`
	Issued       bool     `json:"issued"`
	Certificate  string   `json:"certificate,omitempty"`
	PrivateKey   string   `json:"private_key,omitempty"`
	CertFilename string   `json:"cert_filename,omitempty"`
	KeyFilename  string   `json:"key_filename,omitempty"`
}

// Certificate Config CRUD
func (c *Client) GetCertificates(ctx context.Context) ([]CertConfig, error) {
	var resp []CertConfig
	err := c.sendRequest(ctx, "GET", "/api/v1/config/certificates", nil, &resp)
	return resp, err
}

func (c *Client) CreateCertificate(ctx context.Context, cert CertConfig) error {
	return c.sendRequest(ctx, "POST", "/api/v1/config/certificates", cert, nil)
}

func (c *Client) UpdateCertificate(ctx context.Context, primary string, cert CertConfig) error {
	path := fmt.Sprintf("/api/v1/config/certificates/%s", primary)
	return c.sendRequest(ctx, "PUT", path, cert, nil)
}

func (c *Client) DeleteCertificate(ctx context.Context, primary string) error {
	path := fmt.Sprintf("/api/v1/config/certificates/%s", primary)
	return c.sendRequest(ctx, "DELETE", path, nil, nil)
}

// API Key Config CRUD
func (c *Client) GetAPIKeys(ctx context.Context) ([]APIKeyConfig, error) {
	var resp []APIKeyConfig
	err := c.sendRequest(ctx, "GET", "/api/v1/config/api_keys", nil, &resp)
	return resp, err
}

func (c *Client) CreateAPIKey(ctx context.Context, key APIKeyConfig) error {
	return c.sendRequest(ctx, "POST", "/api/v1/config/api_keys", key, nil)
}

func (c *Client) UpdateAPIKey(ctx context.Context, key APIKeyConfig) error {
	return c.sendRequest(ctx, "PUT", "/api/v1/config/api_keys", key, nil)
}

func (c *Client) DeleteAPIKey(ctx context.Context, token string) error {
	path := fmt.Sprintf("/api/v1/config/api_keys?token=%s", token)
	return c.sendRequest(ctx, "DELETE", path, nil, nil)
}

func (c *Client) GetCertificateData(ctx context.Context) ([]CertificateData, error) {
	var resp []CertificateData
	err := c.sendRequest(ctx, "GET", "/api/v1/certificates", nil, &resp)
	return resp, err
}

