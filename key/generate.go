package key

import (
	crypto_rand "crypto/rand"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
	"io"

	"git.samanthony.xyz/hose/util"
)

// A keyGenerator generates a new keypair from a random bitstream.
type keyGenerator func(rand io.Reader) (publicKey, privateKey []byte, err error)

// generateKeypair uses a key generator function to create a new public/private keypair.
// The public key is saved to the public file, and the private key is saved to the private file.
// If either of the files already exist, an error is returned.
func generateKeypair(generate keyGenerator, pubFileName, privFileName string) error {
	// Create public key file.
	pubFile, err := createFileIfNotExist(pubFileName, pubFileMode)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	// Create private key file.
	privFile, err := createFileIfNotExist(privFileName, privFileMode)
	if err != nil {
		return err
	}
	defer privFile.Close()

	// Generate keypair.
	pubkey, privkey, err := generate(crypto_rand.Reader)
	if err != nil {
		return err
	}

	// Write keypair to files.
	buf := encode(pubkey)
	if _, err := pubFile.Write(buf); err != nil {
		return err
	}
	buf = encode(privkey)
	if _, err := privFile.Write(buf); err != nil {
		return err
	}

	return nil
}

// If neither the public file nor private file exist, generateKeypair uses the key generator
// function to create a new keypair. The public key is saved to the public key file,
// and the private key is saved to the private key file.
func generateKeypairIfNotExist(generate keyGenerator, pubFile, privFile string) error {
	pubExists, err := fileExists(pubFile)
	if err != nil {
		return err
	}
	privExists, err := fileExists(privFile)
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
	return generateKeypair(generate, pubFile, privFile)
}

// generateBoxKeypair generates a new public/private keypair for NaCl box
// (encryption/decryption) operations.  It stores the private key in the private box
// key file and the public box key in the public key file.  If either of the key files
// already exist, they will not be overwritten; instead an error will be returned.
func generateBoxKeypair() error {
	return generateKeypair(boxKeyGenerator, boxPubKeyFile, boxPrivKeyFile)
}

// generateBoxKeypairIfNotExist generates a NaCal box keypair if it doesn't already exist.
func generateBoxKeypairIfNotExist() error {
	return generateKeypairIfNotExist(boxKeyGenerator, boxPubKeyFile, boxPrivKeyFile)
}

// NaCl box (encrypt/decrypt) keypair generator for use with generateKeypair().
func boxKeyGenerator(rand io.Reader) (publicKey, privateKey []byte, err error) {
	util.Logf("generating new encryption/decryption keypair...")
	pub, priv, err := box.GenerateKey(rand)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	return (*pub)[:], (*priv)[:], nil
}

// generateSigKeypair generates a new NaCl sign/verify keypair.
// It stores the private signing key in the private signing key file
// and the public verification key in the public verification key file.
// If either of the key files already exist, they will not be overwritten;
// instead an error will be returned.
func generateSigKeypair() error {
	util.Logf("generating new sign/verify keypair...")
	return generateKeypair(sigKeyGenerator, sigPubKeyFile, sigPrivKeyFile)
}

// generateSigKeypairIfNotExist generates a NaCl sign/verify keypair if it doesn't already exist.
func generateSigKeypairIfNotExist() error {
	return generateKeypairIfNotExist(sigKeyGenerator, sigPubKeyFile, sigPrivKeyFile)
}

// NaCl sign/verify keypair generator for use with generateKeypair().
func sigKeyGenerator(rand io.Reader) (publicKey, privateKey []byte, err error) {
	pub, priv, err := sign.GenerateKey(rand)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	return (*pub)[:], (*priv)[:], nil
}
