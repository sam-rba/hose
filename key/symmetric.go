package key

import (
	crypto_rand "crypto/rand"
	"crypto/sha3"
	"github.com/keybase/saltpack"
	"io"
)

func NewReceiverSymmetricKey() (saltpack.ReceiverSymmetricKey, error) {
	var key saltpack.SymmetricKey
	if _, err := io.ReadFull(crypto_rand.Reader, key[:]); err != nil {
		return saltpack.ReceiverSymmetricKey{}, err
	}

	id := sha3.Sum512(key[:])

	return saltpack.ReceiverSymmetricKey{key, id[:]}, nil
}
