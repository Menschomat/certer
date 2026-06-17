package cert

import (
	"crypto/ecdsa"
	"testing"
)

func TestNewUser(t *testing.T) {
	email := "test@example.com"
	user, err := NewUser(email)
	if err != nil {
		t.Fatalf("Failed to create new user: %v", err)
	}

	if user.GetEmail() != email {
		t.Errorf("Expected email %q; got %q", email, user.GetEmail())
	}

	if user.GetRegistration() != nil {
		t.Errorf("Expected registration to be nil; got %v", user.GetRegistration())
	}

	key := user.GetPrivateKey()
	if key == nil {
		t.Fatal("Expected private key to be generated, got nil")
	}

	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Expected private key to be ecdsa.PrivateKey; got %T", key)
	}
}
