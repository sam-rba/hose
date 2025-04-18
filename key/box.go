package key

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/keybase/saltpack"
	"github.com/keybase/saltpack/basic"
)

// BoxPublicKey is a public NaCl box key.
type BoxPublicKey [32]byte

// BoxPrivateKey is a private NaCl box key.
type BoxPrivateKey [32]byte

type BoxKeypair struct {
	Public  BoxPublicKey
	Private BoxPrivateKey
}

// LoadBoxKeypair reads the public and private NaCl box keys from disc,
// or generates a new keypair if it does not already exist.
// These keys can be used for NaCl box (encryption/decryption) operations.
func LoadBoxKeypair() (BoxKeypair, error) {
	err := generateBoxKeypairIfNotExist()
	if err != nil {
		return BoxKeypair{}, err
	}

	pub, err := loadBoxKey(boxPubKeyFile)
	if err != nil {
		return BoxKeypair{}, err
	}

	priv, err := loadBoxKey(boxPrivKeyFile)
	if err != nil {
		return BoxKeypair{}, err
	}

	return BoxKeypair{pub, priv}, nil
}

// LoadBoxPublicKey reads the public NaCl box key from disc,
// or generates a new keypair if it does not already exist.
func LoadBoxPublicKey() (BoxPublicKey, error) {
	err := generateBoxKeypairIfNotExist()
	if err != nil {
		return BoxPublicKey{}, err
	}
	key, err := loadBoxKey(boxPubKeyFile)
	return BoxPublicKey(key), err
}

// loadBoxKey reads a NaCl box key (public or private)  from the specified file.
func loadBoxKey(filename string) ([32]byte, error) {
	return loadKey(filename, decodeBoxKey)
}

func (bpk1 BoxPublicKey) Compare(bpk2 BoxPublicKey) int {
	return bytes.Compare(bpk1[:], bpk2[:])
}

func DecodeBoxPublicKey(buf []byte) (BoxPublicKey, error) {
	key, err := decodeBoxKey(buf)
	return BoxPublicKey(key), err
}

func decodeBoxKey(buf []byte) ([32]byte, error) {
	var key [32]byte
	if hex.DecodedLen(len(buf)) != len(key) {
		return [32]byte{}, fmt.Errorf("malformed box key: expected %d bytes; got %d",
			len(key), hex.DecodedLen(len(buf)))
	}
	if _, err := hex.Decode(key[:], buf); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

func (key BoxPublicKey) ToKID() []byte {
	return key[:]
}

func (key BoxPublicKey) CreateEphemeralKey() (saltpack.BoxSecretKey, error) {
	return basic.EphemeralKeyCreator{}.CreateEphemeralKey()
}

func (key BoxPublicKey) ToRawBoxKeyPointer() *saltpack.RawBoxKey {
	raw := saltpack.RawBoxKey(key)
	return &raw
}

func (key BoxPublicKey) HideIdentity() bool {
	return false
}

func (pair BoxKeypair) Box(receiver saltpack.BoxPublicKey, nonce saltpack.Nonce, msg []byte) []byte {
	return pair.secretKey().Box(receiver, nonce, msg)
}

func (pair BoxKeypair) Unbox(sender saltpack.BoxPublicKey, nonce saltpack.Nonce, msg []byte) ([]byte, error) {
	return pair.secretKey().Unbox(sender, nonce, msg)
}

func (pair BoxKeypair) GetPublicKey() saltpack.BoxPublicKey {
	return pair.Public
}

func (pair BoxKeypair) Precompute(peer saltpack.BoxPublicKey) saltpack.BoxPrecomputedSharedKey {
	return pair.secretKey().Precompute(peer)
}

func (pair BoxKeypair) secretKey() saltpack.BoxSecretKey {
	pub, sec := [32]byte(pair.Public), [32]byte(pair.Private)
	return basic.NewSecretKey(&pub, &sec)
}
