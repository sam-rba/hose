package key

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// BoxPublicKey is a public NaCl box key.
type BoxPublicKey [32]byte

// BoxPrivateKey is a private NaCl box key.
type BoxPrivateKey [32]byte

// LoadBoxKeypair reads the public and private NaCl box keys from disc,
// or generates a new keypair if it does not already exist.
// These keys can be used for NaCl box (encryption/decryption) operations.
func LoadBoxKeypair() (pub BoxPublicKey, priv BoxPrivateKey, err error) {
	// Generate a keypair if it doesn't already exist.
	err = generateBoxKeypairIfNotExist()
	if err != nil {
		return
	}

	pub, err = loadBoxKey(boxPubKeyFile)
	if err != nil {
		return
	}

	priv, err = loadBoxKey(boxPrivKeyFile)

	return
}

// LoadBoxPublicKey reads the public NaCl box key from disc,
// or generates a new keypair if it does not already exist.
func LoadBoxPublicKey() (BoxPublicKey, error) {
	key, err := loadBoxKey(boxPubKeyFile)
	return BoxPublicKey(key), err
}

// loadBoxKey reads a NaCl box key (public or private)  from the specified file.
func loadBoxKey(filename string) ([32]byte, error) {
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
