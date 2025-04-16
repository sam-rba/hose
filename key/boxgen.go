package key

import (
	crypto_rand "crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"os"

	"git.samanthony.xyz/hose/util"
)

// generateBoxKeypair generates a new public/private keypair for NaCl box
// (encryption/decryption) operations.  It stores the private key in the private box
// key file and the public box key in the public key file.  If either of the key files
// already exist, they will not be overwritten; instead an error will be returned.
func generateBoxKeypair() error {
	util.Logf("generating new encryption/decryption keypair...")

	// Create public key file.
	pubFile, err := createFileIfNotExist(boxPubKeyFile, pubFileMode)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	// Create private key file.
	privFile, err := createFileIfNotExist(boxPrivKeyFile, privFileMode)
	if err != nil {
		pubFile.Close()
		_ = os.Remove(boxPubKeyFile)
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

// generateBoxKeypairIfNotExist generates a NaCal box keypair if it doesn't already exist.
func generateBoxKeypairIfNotExist() error {
	pubExists, err := fileExists(boxPubKeyFile)
	if err != nil {
		return err
	}
	privExists, err := fileExists(boxPrivKeyFile)
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
	return generateBoxKeypair()
}
