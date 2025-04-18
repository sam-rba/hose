package key

import (
	"io"
	"os"
)

// loadKey reads and decodes a key from a file.
func loadKey[K any](filename string, decode func([]byte) (K, error)) (K, error) {
	var key K

	f, err := os.Open(filename)
	if err != nil {
		return key, err
	}
	defer f.Close()

	buf, err := io.ReadAll(f)
	if err != nil {
		return key, err
	}

	return decode(buf)
}
