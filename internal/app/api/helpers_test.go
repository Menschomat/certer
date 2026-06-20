package api

import (
	"os"
	"path/filepath"
	"testing"
)

// Common token hashes and values used in tests.
const (
	testAdminToken = "blabliblub"
	testAdminHash  = "$argon2id$v=19$m=65536,t=3,p=2$5e3EMry5f9M8wHWfOI3uOA$EoHEmZt426KKoow/3j7a4o0Yo/oKdZwGpNy+FTowmTs"
)

// setupTestEnv initializes a temporary directory for configuration files, sets the CONFIG_PATH env var,
// and returns the directory path along with a cleanup function.
func setupTestEnv(t *testing.T, prefix string) (string, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	configPath := filepath.Join(tmpDir, "config.json")
	os.Setenv("CONFIG_PATH", configPath)
	return tmpDir, func() {
		os.Unsetenv("CONFIG_PATH")
		os.RemoveAll(tmpDir)
	}
}
