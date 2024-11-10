package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	
	"github.com/roshanpaturkar/cryptifygo/utils/pkcs"
)

// Encrypt the message and return key, iv and encrypted message in base64 format
func Encrypt(message []byte) ([]byte, []byte, []byte, error) {
	// Generate a random 32 byte key and 16 byte iv
	key := make([]byte, 32)
	iv := make([]byte, 16)
	
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, nil, err
	}

	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, nil, err
	}	
	
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Pad the message with PKCS7 padding
	message = pkcs.Pkcs7Padding(message, aes.BlockSize)
	ciphertext := make([]byte, len(message))

	// Encrypt the message with AES
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, message)
	
	// Return the key, iv and ciphertext
	return key, iv, ciphertext, nil
}

// Decrypt the message with key, iv and encrypted message in base64 format and return the decrypted message
func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Check if the ciphertext is valid
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	
	// Check if the ciphertext is a multiple of the block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	// Decrypt the message with AES
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Unpad the message with PKCS7 padding and return
	return pkcs.Pkcs7UnPadding(plaintext)
}