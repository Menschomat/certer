package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2TimeCost = 3
	argon2Memory   = 65536
	argon2Threads  = 2
	argon2KeyLen   = 32
	argon2SaltLen  = 16
)

// GenerateArgon2idHash generates a standard encoded Argon2id hash for a token.
func GenerateArgon2idHash(token string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(token), salt, argon2TimeCost, argon2Memory, argon2Threads, argon2KeyLen)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argon2Memory, argon2TimeCost, argon2Threads, encodedSalt, encodedHash), nil
}

// VerifyToken compares a plain text token against a stored Argon2id hash.
func VerifyToken(plainToken, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid Argon2id hash format")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("unsupported Argon2 variant")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, fmt.Errorf("incompatible argon2 version %d", version)
	}

	var memory, timeCost uint32
	var threads uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	actualHash := argon2.IDKey([]byte(plainToken), salt, timeCost, memory, threads, uint32(len(expectedHash)))

	if subtle.ConstantTimeCompare(actualHash, expectedHash) == 1 {
		return true, nil
	}
	return false, nil
}
