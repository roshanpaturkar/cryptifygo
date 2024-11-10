package pkcs

import (
	"bytes"
	"errors"
)

// PKCS7 padding
func Pkcs7Padding(data []byte, blockSize int) []byte {
	// Calculate padding size
	padding := blockSize - len(data)%blockSize
	
	// Create padding text
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	
	// Append padding text to data and return
	return append(data, padtext...)
}

// PKCS7 unpadding
func Pkcs7UnPadding(data []byte) ([]byte, error) {
	// Get padding size
	length := len(data)
	if length == 0 {
		return nil, errors.New("data is empty")
	}
	
	// Check if the data is padded with valid PKCS7 padding
	unpadding := int(data[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, errors.New("invalid padding size")
	}
	
	// Return unpadded data
	return data[:length-unpadding], nil
}