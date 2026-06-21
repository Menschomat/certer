package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"certer/internal/app/api"
)

func main() {
	tokenFlag := flag.String("token", "", "Plain-text token to hash. If empty, a random token is generated.")
	flag.Parse()

	token := *tokenFlag
	generated := false

	if token == "" {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			fmt.Printf("Error generating random token: %v\n", err)
			os.Exit(1)
		}
		token = hex.EncodeToString(bytes)
		generated = true
	}

	hash, err := api.GenerateArgon2idHash(token)
	if err != nil {
		fmt.Printf("Error generating Argon2id hash: %v\n", err)
		os.Exit(1)
	}

	if generated {
		fmt.Printf("Generated plain-text token: %s\n", token)
	}
	fmt.Printf("Argon2id Hash (paste into config.json):\n%s\n", hash)
}
