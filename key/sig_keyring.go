package key

import (
	"bytes"
	"github.com/keybase/saltpack"
	"slices"
)

type SigKeyring []SigPublicKey

func (ring *SigKeyring) Import(key SigPublicKey) {
	i, ok := slices.BinarySearchFunc(*ring, key, cmpSigPublicKey)
	if ok {
		return // key already in keyring.
	}
	*ring = slices.Insert(*ring, i, key)
}

func (ring SigKeyring) LookupSigningPublicKey(kid []byte) saltpack.SigningPublicKey {
	if len(kid) != len(SigPublicKey{}) {
		return nil
	}
	key := SigPublicKey(kid)
	i, ok := slices.BinarySearchFunc(ring, key, cmpSigPublicKey)
	if !ok {
		return nil // key not in keyring.
	}
	return ring[i]
}

func cmpSigPublicKey(a, b SigPublicKey) int {
	return bytes.Compare(a[:], b[:])
}
