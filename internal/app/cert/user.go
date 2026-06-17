package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/go-acme/lego/v5/acme"
)

// User implements registration.User interface.
type User struct {
	Email        string
	Registration *acme.ExtendedAccount
	key          crypto.PrivateKey
}

// NewUser creates a User with a new ECDSA private key.
func NewUser(email string) (*User, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &User{
		Email: email,
		key:   privateKey,
	}, nil
}

// GetEmail returns the user email.
func (u *User) GetEmail() string {
	return u.Email
}

// GetRegistration returns the registration resource.
func (u *User) GetRegistration() *acme.ExtendedAccount {
	return u.Registration
}

// GetPrivateKey returns the private key as a crypto.Signer.
func (u *User) GetPrivateKey() crypto.Signer {
	signer, ok := u.key.(crypto.Signer)
	if !ok {
		return nil
	}
	return signer
}
