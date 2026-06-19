package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_SendRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}

		if r.URL.Path == "/test" {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "success"})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "test-token")

	t.Run("Success Path", func(t *testing.T) {
		var resp map[string]string
		err := c.sendRequest(context.Background(), "GET", "/test", nil, &resp)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if resp["message"] != "success" {
			t.Errorf("Expected message 'success', got %q", resp["message"])
		}
	})

	t.Run("Unauthorized Path", func(t *testing.T) {
		badClient := NewClient(ts.URL, "bad-token")
		err := badClient.sendRequest(context.Background(), "GET", "/test", nil, nil)
		if err == nil {
			t.Fatal("Expected error, got nil")
		}
	})
}
