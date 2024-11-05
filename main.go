package cryptifygo

import (
	"encoding/base64"
	
	"github.com/roshanpaturkar/cryptifygo/utils/aes"
	"github.com/roshanpaturkar/cryptifygo/utils/rsa"
)

// Take the message and RSA public key as input as strings
// Encrypt the message with AES and return key, iv and encrypted message in base64 format
// The key is encrypted with RSA
// convert the key, iv and encrypted message to base64 format
// return as map[string]string
func Encrypt(message, publicKey string) (map[string]string, error) {
	// Encrypt the message with AES
	key, iv, ciphertext, err := aes.Encrypt([]byte(message))
	if err != nil {
		return nil, err
	}

	// Encrypt the key with RSA
	encryptedKey, err := rsa.Encrypt(publicKey, []byte(key))
	if err != nil {
		return nil, err
	}

	// Return the key, iv and ciphertext in base64 format
	return map[string]string{
		"key":       encryptedKey,
		"iv":        iv,
		"ciphertext": ciphertext,
	}, nil
}

// Take the key, iv, ciphertext and RSA private key as input as strings
// Decrypt the key with RSA
// Decrypt the message with AES
// Return the decrypted message as a string
// Return an error if any
func Decrypt(key, iv, ciphertext, privateKey string) (string, error) {
	// Decrypt the key with RSA
	decryptedKey, err := rsa.Decrypt(privateKey, []byte(key))
	if err != nil {
		return "", err
	}

	// DEcode decodedKey from base64
	decryptedKey_decoded, err := base64.StdEncoding.DecodeString(decryptedKey)
	if err != nil {
		return "", err
	}
	
	// Decode the iv and ciphertext from base64
	iv_decoded, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return "", err
	}
	
	ciphertext_decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Decrypt the message with AES
	plaintext, err := aes.Decrypt(decryptedKey_decoded, iv_decoded, ciphertext_decoded)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
