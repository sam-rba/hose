package key

import "encoding/hex"

func encode(key []byte) []byte {
	buf := make([]byte, hex.EncodedLen(len(key)))
	hex.Encode(buf, key)
	return buf
}
