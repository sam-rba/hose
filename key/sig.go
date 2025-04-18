package key

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/keybase/saltpack"
	"github.com/keybase/saltpack/basic"
)

// SigPublicKey is a public NaCl signature verification key.
type SigPublicKey [32]byte

// SigPrivateKey is a private NaCl signing key.
type SigPrivateKey [64]byte

type SigKeypair struct {
	public  SigPublicKey
	private SigPrivateKey
}

// LoadSigKeypair reads the public and private NaCl signature keys from disc,
// or generates a new keypair if it does not already exist.
func LoadSigKeypair() (SigKeypair, error) {
	err := generateSigKeypairIfNotExist()
	if err != nil {
		return SigKeypair{}, err
	}

	pub, err := loadKey(sigPubKeyFile, DecodeSigPublicKey)
	if err != nil {
		return SigKeypair{}, err
	}

	priv, err := loadKey(sigPrivKeyFile, DecodeSigPrivateKey)
	if err != nil {
		return SigKeypair{}, err
	}

	return SigKeypair{pub, priv}, nil
}

// LoadSigPublicKey reads the public signature verification key from disc,
// or generates a new keypair if it does not already exist.
func LoadSigPublicKey() (SigPublicKey, error) {
	// Generate keypair if it doesn't already exist.
	err := generateSigKeypairIfNotExist()
	if err != nil {
		return SigPublicKey{}, err
	}
	return loadKey(sigPubKeyFile, DecodeSigPublicKey)
}

// LoadSigPrivateKey reads the private signing key from disc,
// or generates a new keypair if it does not already exist.
func LoadSigPrivateKey() (SigPrivateKey, error) {
	// Generate keypair if it doesn't already exist.
	err := generateSigKeypairIfNotExist()
	if err != nil {
		return SigPrivateKey{}, err
	}
	return loadKey(sigPrivKeyFile, DecodeSigPrivateKey)
}

func (spk1 SigPublicKey) Compare(spk2 SigPublicKey) int {
	return bytes.Compare(spk1[:], spk2[:])
}

func DecodeSigPublicKey(buf []byte) (SigPublicKey, error) {
	var key SigPublicKey
	if hex.DecodedLen(len(buf)) != len(key) {
		return SigPublicKey{}, fmt.Errorf("malformed signature verification key: expected %d bytes; got %d",
			len(key), hex.DecodedLen(len(buf)))
	}
	if _, err := hex.Decode(key[:], buf); err != nil {
		return SigPublicKey{}, err
	}
	return key, nil
}

func DecodeSigPrivateKey(buf []byte) (SigPrivateKey, error) {
	var key SigPrivateKey
	if hex.DecodedLen(len(buf)) != len(key) {
		return SigPrivateKey{}, fmt.Errorf("malformed signing key: expected %d bytes; got %d",
			len(key), hex.DecodedLen(len(buf)))
	}
	if _, err := hex.Decode(key[:], buf); err != nil {
		return SigPrivateKey{}, err
	}
	return key, nil
}

func (pair SigKeypair) Sign(message []byte) ([]byte, error) {
	public := [ed25519.PublicKeySize]byte(pair.public)
	private := [ed25519.PrivateKeySize]byte(pair.private)
	key := basic.NewSigningSecretKey(&public, &private)
	return key.Sign(message)
}

func (pair SigKeypair) GetPublicKey() saltpack.SigningPublicKey {
	public := [ed25519.PublicKeySize]byte(pair.public)
	return basic.NewSigningPublicKey(&public)
}

func (key SigPublicKey) ToKID() []byte {
	return key[:]
}

func (key SigPublicKey) Verify(message []byte, signature []byte) error {
	raw := [ed25519.PublicKeySize]byte(key)
	return basic.NewSigningPublicKey(&raw).Verify(message, signature)
}
