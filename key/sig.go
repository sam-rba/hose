package key

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// SigPublicKey is a public NaCl signature verification key.
type SigPublicKey [32]byte

// SigPrivateKey is a private NaCl signing key.
type SigPrivateKey [64]byte

// LoadSigPublicKey reads the public signature verification key from disc,
// or generates a new keypair if it does not already exist.
func LoadSigPublicKey() (SigPublicKey, error) {
	// Generate keypair if it doesn't already exist.
	err := generateSigKeypairIfNotExist()
	if err != nil {
		return SigPublicKey{}, err
	}

	// Open public key file.
	f, err := os.Open(sigPubKeyFile)
	if err != nil {
		return SigPublicKey{}, err
	}
	defer f.Close()

	// Read key from file.
	buf, err := io.ReadAll(f)
	if err != nil {
		return SigPublicKey{}, err
	}

	// Decode key.
	var key SigPublicKey
	if hex.DecodedLen(len(buf)) != len(key) {
		return SigPublicKey{}, fmt.Errorf("malformed key: expected %d bytes; got %d",
			len(key), hex.DecodedLen(len(buf)))
	}
	if _, err := hex.Decode(key[:], buf); err != nil {
		return SigPublicKey{}, err
	}

	return key, nil
}

func (spk1 SigPublicKey) Compare(spk2 SigPublicKey) int {
	return bytes.Compare(spk1[:], spk2[:])
}
