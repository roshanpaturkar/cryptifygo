package pkcs

import (
	"bytes"
	"errors"
)

// PKCS7 padding
func Pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7 unpadding
func Pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("data is empty")
	}
	unpadding := int(data[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, errors.New("invalid padding size")
	}
	return data[:length-unpadding], nil
}