package cryptifygo

import (
	"encoding/base64"
	
	"github.com/roshanpaturkar/cryptifygo/utils/aes"
	"github.com/roshanpaturkar/cryptifygo/utils/rsa"
)

// Take the message and RSA public key as input as strings.
// Encrypt the message with AES and return key, iv and encrypted message in base64 format.
// The key is encrypted with RSA.
// convert the key, iv and encrypted message to base64 format.
// return as map[string]string and error if any.
func Encrypt(message, publicKey string) (map[string]string, error) {
	// Encrypt the message with AES
	key, iv, ciphertext, err := aes.Encrypt([]byte(message))
	if err != nil {
		return nil, err
	}

	// Decode the public key from base64
	publicKey_decoded, err := base64.StdEncoding.DecodeString(publicKey)

	// Encrypt the key with RSA
	encryptedKey, err := rsa.Encrypt(publicKey_decoded, key)
	if err != nil {
		return nil, err
	}

	// Return the map of key, iv and ciphertext in base64 format
	return map[string]string{
		"key":       base64.StdEncoding.EncodeToString(encryptedKey),
		"iv":        base64.StdEncoding.EncodeToString(iv),
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// Take the key, iv, ciphertext and RSA private key as input as strings.
// Decrypt the key with RSA.
// Decrypt the message with AES.
// Return the decrypted message as a string and error if any.
func Decrypt(key, iv, ciphertext, privateKey string) (string, error) {
	// Decode the private key from base64 format
	privateKey_decoded, err := base64.StdEncoding.DecodeString(privateKey)

	// Decode the key from base64 format
	key_decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}

	// Decrypt the key with RSA private key
	decryptedKey, err := rsa.Decrypt(privateKey_decoded, key_decoded)
	if err != nil {
		return "", err
	}

	// Decode the iv and ciphertext from base64 format
	iv_decoded, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return "", err
	}
	
	// Decode the ciphertext from base64 format
	ciphertext_decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Decrypt the message with AES key and iv
	plaintext, err := aes.Decrypt(decryptedKey, iv_decoded, ciphertext_decoded)
	if err != nil {
		return "", err
	}

	// Return the decrypted message as a string
	return string(plaintext), nil
}
