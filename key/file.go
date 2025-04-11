package key

import (
	"errors"
	"fmt"
	"github.com/adrg/xdg"
	"os"
	"path/filepath"

	"git.samanthony.xyz/hose/util"
)

var (
	pubKeyFile                 = filepath.Join(xdg.DataHome, "hose", "pubkey")
	pubKeyFileMode os.FileMode = 0644

	privKeyFile                 = filepath.Join(xdg.DataHome, "hose", "privkey")
	privKeyFileMode os.FileMode = 0600

	dirMode os.FileMode = 0755
)

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

	util.Logf("creating file %s with mode %o", name, mode)

	// Create directory.
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, err
	}

	// Create file.
	f, err := os.Create(name)
	if err != nil {
		return nil, err
	}

	// Set mode.
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
