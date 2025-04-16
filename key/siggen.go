package key

import (
	crypto_rand "crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/nacl/sign"

	"git.samanthony.xyz/hose/util"
)

func generateSigKeypair() error {
	util.Logf("generating new sign/verify keypair...")

	// Create public key file.
	pubFile, err := createFileIfNotExist(sigPubKeyFile, pubFileMode)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	// Create private key file.
	privFile, err := createFileIfNotExist(sigPrivKeyFile, privFileMode)
	if err != nil {
		return err
	}
	defer privFile.Close()

	// Generate keypair.
	pubkey, privkey, err := sign.GenerateKey(crypto_rand.Reader)
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
