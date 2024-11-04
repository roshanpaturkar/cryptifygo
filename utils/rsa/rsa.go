package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"
	"errors"
)

// Encrypt the message with the public key
// The public key is in PEM format
// The message is in plain text
// Return encrypted message is in base64 format
func Encrypt(publicKey string, message []byte) (string, error) {
	// Decode the public key
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return "", errors.New("failed to decode the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("not an RSA public key")
	}

	hash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		rsaPub,
		message,
		nil,
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt the message with the private key
// The private key is in PEM format
// The message is in base64 format
// Return decrypted message in plain text
func Decrypt(privateKey string, ciphertext []byte) (string, error) {
	
	ciphertext, err := base64.StdEncoding.DecodeString(string(ciphertext))
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", errors.New("failed to decode private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("not an RSA private key")
	}

	hash := sha256.New()

	plaintext, err := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		rsaPriv,
		ciphertext,
		nil,
	)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}