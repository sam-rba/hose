package key

import (
	crypto_rand "crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"os"

	"git.samanthony.xyz/hose/util"
)

// Generate generates a new public/private keypair. It stores the private key in the
// private key file and the public key in the public key file.  If either of the key
// files already exist, they will not be overwritten; instead an error will be returned.
func Generate() error {
	util.Logf("generating new keypair...")

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
	buf := make([]byte, hex.EncodedLen(len(*pubkey)))
	hex.Encode(buf, (*pubkey)[:])
	if _, err := pubFile.Write(buf); err != nil {
		return err
	}
	buf = make([]byte, hex.EncodedLen(len(*privkey)))
	hex.Encode(buf, (*privkey)[:])
	if _, err := privFile.Write(buf); err != nil {
		return err
	}

	return nil
}

// Generate a keypair if it doesn't already exist.
func generateIfNoExist() error {
	pubExists, err := fileExists(pubKeyFile)
	if err != nil {
		return err
	}
	privExists, err := fileExists(privKeyFile)
	if err != nil {
		return err
	}

	if pubExists && privExists {
		// Keypair already exists.
		return nil
	} else if pubExists && !privExists {
		return fmt.Errorf("found public key file but not private key file")
	} else if privExists && !pubExists {
		return fmt.Errorf("found private key file but not public key file")
	}
	// Neither public nor private key file exists; generate new keypair.
	return Generate()
}
