package key

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// LoadKeypair reads the public and private keys from disc,
// or generates a new keypair if it does not already exist.
func LoadKeypair() (public, private [32]byte, err error) {
	// Generate a keypair if it doesn't already exist.
	err = generateIfNoExist()
	if err != nil {
		return
	}

	public, err = loadKey(pubKeyFile)
	if err != nil {
		return
	}

	private, err = loadKey(privKeyFile)

	return
}

// LoadPublicKey reads the public key from disc, or generates a new keypair
// if it does not already exist.
func LoadPublicKey() ([32]byte, error) {
	return loadKey(pubKeyFile)
}

// loadKey reads a key (public or private) from the specified file.
func loadKey(filename string) ([32]byte, error) {
	// Open file.
	f, err := os.Open(filename)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	// Read key from file.
	buf, err := io.ReadAll(f)
	if err != nil {
		return [32]byte{}, err
	}

	// Decode key.
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
