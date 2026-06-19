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

func TestClient_CRUD(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/config/certificates" {
			if r.Method == "GET" {
				_ = json.NewEncoder(w).Encode([]CertConfig{{Primary: "test.com"}})
			} else if r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
			}
			return
		}
		if r.URL.Path == "/api/v1/config/certificates/test.com" {
			if r.Method == "PUT" {
				w.WriteHeader(http.StatusOK)
			} else if r.Method == "DELETE" {
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}
		if r.URL.Path == "/api/v1/certificates" && r.Method == "GET" {
			_ = json.NewEncoder(w).Encode([]CertificateData{{Domain: "test.com", Certificate: "PEM"}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := NewClient(ts.URL, "token")

	t.Run("Certificates", func(t *testing.T) {
		certs, err := c.GetCertificates(context.Background())
		if err != nil || len(certs) != 1 || certs[0].Primary != "test.com" {
			t.Errorf("GetCertificates failed: %v, certs: %+v", err, certs)
		}

		err = c.CreateCertificate(context.Background(), CertConfig{Primary: "new.com"})
		if err != nil {
			t.Errorf("CreateCertificate failed: %v", err)
		}

		err = c.UpdateCertificate(context.Background(), "test.com", CertConfig{Sans: []string{"www.test.com"}})
		if err != nil {
			t.Errorf("UpdateCertificate failed: %v", err)
		}

		err = c.DeleteCertificate(context.Background(), "test.com")
		if err != nil {
			t.Errorf("DeleteCertificate failed: %v", err)
		}
	})

	t.Run("CertificateData", func(t *testing.T) {
		data, err := c.GetCertificateData(context.Background())
		if err != nil || len(data) != 1 || data[0].Certificate != "PEM" {
			t.Errorf("GetCertificateData failed: %v, data: %+v", err, data)
		}
	})
}

