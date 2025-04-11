package main

import "crypto/sha256"

func fingerprint(key []byte) []byte {
	return sha256.New().Sum(key)
}
