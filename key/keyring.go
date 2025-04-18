package key

import (
	"bytes"
	"github.com/keybase/saltpack"
	"slices"
)

type Keyring struct {
	keyCreator saltpack.EphemeralKeyCreator
	boxKeys    []BoxKeypair   // list of box keypairs sorted by public key.
	sigPubKeys []SigPublicKey // sorted list of public verification keys.
}

func NewKeyring() *Keyring {
	return new(Keyring)
}

func (ring *Keyring) ImportBoxKeypair(pair BoxKeypair) {
	i, ok := slices.BinarySearchFunc(ring.boxKeys, pair.Public, cmpBoxKeypairPubKey)
	if ok {
		return // key already in keyring.
	}
	ring.boxKeys = slices.Insert(ring.boxKeys, i, pair)
}

func (ring *Keyring) ImportSigPublicKey(key SigPublicKey) {
	i, ok := slices.BinarySearchFunc(ring.sigPubKeys, key, cmpSigPublicKey)
	if ok {
		return // key already in keyring.
	}
	ring.sigPubKeys = slices.Insert(ring.sigPubKeys, i, key)
}

func (ring *Keyring) CreateEphemeralKey() (saltpack.BoxSecretKey, error) {
	return ring.keyCreator.CreateEphemeralKey()
}

func (ring *Keyring) LookupBoxSecretKey(kids [][]byte) (int, saltpack.BoxSecretKey) {
	for _, kid := range kids {
		var pub BoxPublicKey
		if len(kid) != len(pub) {
			continue
		}
		pub = BoxPublicKey(kid)
		i, ok := slices.BinarySearchFunc(ring.boxKeys, pub, cmpBoxKeypairPubKey)
		if ok {
			return i, ring.boxKeys[i]
		}
	}
	return -1, nil
}

func (ring *Keyring) LookupBoxPublicKey(kid []byte) saltpack.BoxPublicKey {
	var pub BoxPublicKey
	if len(kid) != len(pub) {
		return nil
	}
	pub = BoxPublicKey(kid)
	i, ok := slices.BinarySearchFunc(ring.boxKeys, pub, cmpBoxKeypairPubKey)
	if !ok {
		return nil
	}
	return ring.boxKeys[i].Public
}

func (ring *Keyring) GetAllBoxSecretKeys() []saltpack.BoxSecretKey {
	secrets := make([]saltpack.BoxSecretKey, len(ring.boxKeys))
	for i := range ring.boxKeys {
		secrets[i] = ring.boxKeys[i]
	}
	return secrets
}

func (ring *Keyring) ImportBoxEphemeralKey(kid []byte) saltpack.BoxPublicKey {
	var pub BoxPublicKey
	copy(pub[:], kid)
	return pub
}

func (ring *Keyring) LookupSigningPublicKey(kid []byte) saltpack.SigningPublicKey {
	if len(kid) != len(SigPublicKey{}) {
		return nil
	}
	key := SigPublicKey(kid)
	i, ok := slices.BinarySearchFunc(ring.sigPubKeys, key, cmpSigPublicKey)
	if !ok {
		return nil // key not in keyring.
	}
	return ring.sigPubKeys[i]
}

func cmpBoxKeypairPubKey(a BoxKeypair, b BoxPublicKey) int {
	return a.Public.Compare(b)
}

func cmpSigPublicKey(a, b SigPublicKey) int {
	return bytes.Compare(a[:], b[:])
}
