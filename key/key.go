package key

import (
	"encoding/hex"
	"fmt"
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
	buf, err := io.ReadAll(f)
	if err != nil {
		return [32]byte{}, err
	}

	// Decode.
	var key [32]byte
	if hex.DecodedLen(len(buf)) != len(key) {
		return [32]byte{}, fmt.Errorf("malformed key: expected %d bytes; got %d",
			len(key), hex.DecodedLen(len(buf)))
	}
	if _, err := hex.Decode(key[:], buf); err != nil {
		return [32]byte{}, err
	}

	return key, nil
}
