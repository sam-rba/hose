package key

import (
	"io"
	"os"
)

// LoadPublicKey reads the public key from disc, or generates a new keypair
// if it does not already exist.
func LoadPublicKey() ([32]byte, error) {
	// Generate a keypair if it doesn't already exist.
	if err := generateIfNoExist(); err != nil {
		return [32]byte{}, err
	}

	// Open key file.
	f, err := os.Open(pubKeyFile)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	// Read key.
	var pubkey [32]byte
	if _, err := io.ReadFull(f, pubkey[:]); err != nil {
		return [32]byte{}, err
	}
	return pubkey, nil
}
