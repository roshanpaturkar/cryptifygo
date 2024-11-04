package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	
	"github.com/roshanpaturkar/cryptifygo/utils/pkcs"
)

// Encrypt the message and return key, iv and encrypted message in base64 format
func Encrypt(message []byte) (string, string, string, error) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	
	_, err := rand.Read(key)
	if err != nil {
		return "", "", "", err
	}

	_, err = rand.Read(iv)
	if err != nil {
		return "", "", "", err
	}	
		
	block, err := aes.NewCipher(key)
		if err != nil {
			return "", "", "", err
		}

		message = pkcs.Pkcs7Padding(message, aes.BlockSize)
		ciphertext := make([]byte, len(message))

		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext, message)
	
	return base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt the message with key, iv and encrypted message in base64 format
func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		if len(ciphertext) < aes.BlockSize {
			return nil, errors.New("ciphertext too short")
		}

		if len(ciphertext)%aes.BlockSize != 0 {
			return nil, errors.New("ciphertext is not a multiple of the block size")
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		plaintext := make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)

		return pkcs.Pkcs7UnPadding(plaintext)
}