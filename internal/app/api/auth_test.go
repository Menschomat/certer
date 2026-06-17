package api

import (
	"strings"
	"testing"
)

func TestArgon2idHashingAndVerification(t *testing.T) {
	token := "my-secret-token"

	hash, err := GenerateArgon2idHash(token)
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Expected Argon2id format prefix, got: %q", hash)
	}

	// Verify matching token
	match, err := VerifyToken(token, hash)
	if err != nil {
		t.Fatalf("Failed verification process: %v", err)
	}
	if !match {
		t.Error("Expected token to match its hash")
	}

	// Verify mismatching token
	match, err = VerifyToken("wrong-token", hash)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if match {
		t.Error("Expected mismatching token to fail verification")
	}

	// Verify malformed hash error
	_, err = VerifyToken(token, "invalid-hash-string")
	if err == nil {
		t.Error("Expected error for invalid hash format")
	}
}
