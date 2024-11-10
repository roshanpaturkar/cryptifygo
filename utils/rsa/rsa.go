package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Encrypt the message with the public key.
// The public key is in PEM format.
// The message is in plain text.
// Return encrypted message is in base64 format as a byte slice and error if any.
func Encrypt(publicKey []byte, message []byte) ([]byte, error) {
	// Decode the public key from PEM format
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("failed to decode the public key")
	}
	
	// Parse the public key from the PEM block
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Check if the public key is valid RSA public key
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	// Create a new hash
	hash := sha256.New()
	
	// Encrypt the message with the public key
	ciphertext, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		rsaPub,
		message,
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Return the encrypted message
	return ciphertext, nil
}

// Decrypt the message with the private key.
// The private key is in PEM format.
// The message is in base64 format.
// Return decrypted message in plain text as a byte slice and error if any.
func Decrypt(privateKey []byte, ciphertext []byte) ([]byte, error) {
	// Decode the private key from PEM format
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}

	// Parse the private key from the PEM block
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Check if the private key is valid RSA private key
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	// Create a new hash
	hash := sha256.New()

	// Decrypt the message with the private key
	plaintext, err := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		rsaPriv,
		ciphertext,
		nil,
	)
	if err != nil {
		return nil, err
	}
	
	// Return the decrypted message in plain text
	return plaintext, nil
}