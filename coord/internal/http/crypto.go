package http

import (
	crand "crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func cryptoRand(b []byte) (int, error) {
	return crand.Read(b)
}

// x25519ScalarMult computes the X25519 public key from a private key.
func x25519ScalarMult(privKey []byte) ([]byte, error) {
	if len(privKey) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	}
	pub, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
