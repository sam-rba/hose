package key

import (
	crypto_rand "crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
	"golang.org/x/crypto/nacl/box"
)

var (
	pubKeyFile                 = filepath.Join(xdg.DataHome, "hose", "pubkey")
	pubKeyFileMode os.FileMode = 0644

	privKeyFile                 = filepath.Join(xdg.DataHome, "hose", "privkey")
	privKeyFileMode os.FileMode = 0600
)

// Generate generates a new public/private keypair. It stores the private key in the
// private key file and the public key in the public key file.  If either of the key
// files already exist, they will not be overwritten; instead an error will be returned.
func Generate() error {
	// Create public key file.
	pubFile, err := createFile(pubKeyFile, pubKeyFileMode)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	// Create private key file.
	privFile, err := createFile(privKeyFile, privKeyFileMode)
	if err != nil {
		pubFile.Close()
		_ = os.Remove(pubKeyFile)
		return err
	}
	defer privFile.Close()

	// Generate keypair.
	pubkey, privkey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		return err
	}

	// Write keypair to files.
	if _, err := pubFile.Write((*pubkey)[:]); err != nil {
		return err
	}
	if _, err := privFile.Write((*privkey)[:]); err != nil {
		return err
	}

	return nil
}

// createFile creates a file with the specified permissions and returns it for writing.
// It does not truncate an existing file. If the file already exists, an error is returned.
func createFile(name string, mode os.FileMode) (*os.File, error) {
	exists, err := fileExists(name)
	if err != nil {
		return nil, err // unexpected error.
	} else if exists {
		return nil, errFileExists(name) // file exists; do not overwrite.
	}
	// Does not exist; continue;

	f, err := os.Create(name)
	if err != nil {
		return nil, err
	}

	if err := f.Chmod(mode); err != nil {
		f.Close()
		_ = os.Remove(name)
		return nil, err
	}

	return f, nil
}

// fileExists returns a nil error and true/false if a file does/doesn't exist.
// If an error is encountered, a non-nil error is returned.
func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // file doesn't exist.
	} else if err != nil {
		return false, err // unexpected error.
	}
	return true, nil // file exists.
}

// errFileExists constructs a 'file already exists' error message.
func errFileExists(path string) error {
	return fmt.Errorf("%s: %s", os.ErrExist, path)
}
