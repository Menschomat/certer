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
