package api

import (
	"github.com/google/uuid"
)

// GenerateUUIDv7 generates a new RFC 9562 UUIDv7.
func GenerateUUIDv7() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
