# cryptifygo

A simple Go library for encrypting and decrypting data using AES-256-GCM and RSA algorithm.
This library is written in Go and can be used in Go projects. This is very useful when you want to encrypt some sensitive data and store it in a database or send it over the network.
This library is tested with Go projects. And also supported in other languages like Node.js, TypeScript, and the browser. 
For Node.js and TypeScript, you can use the [cryptify-js](https://www.npmjs.com/package/cryptify-js) library.

## Installation
```bash
go get github.com/roshanpaturkar/cryptifygo
```

## Features
- Encrypt and decrypt strings using AES-256-GCM and RSA algorithm.
- Supported in Go, Node.js, TypeScript, and the browser.
- Cross-platform support added Node.js, TypeScript, and the browser. [cryptify-js](https://www.npmjs.com/package/cryptify-js)

## Supported Languages
- Go
- Node.js
- TypeScript
- Browser

### Cross Platform Compatibility Table
| Platform | Compatible Version | Library |
| --- | --- | --- |
| Go | v1.2.0 | [cryptifygo](https://pkg.go.dev/github.com/roshanpaturkar/cryptifygo@v1.2.0#section-readme)
| Node.js | 2.0.0 | [cryptify-js](https://www.npmjs.com/package/cryptify-js)

## Encryption Approach
- Generate a random key and iv for each encryption.
- Encrypt the data using the generated key and iv.
- Encrypt the generated key using the public key.
- Return the encrypted key, iv, and data.

## Decryption Approach
- Decrypt the encrypted key using the private key.
- Decrypt the data using the decrypted key and iv.
- Return the decrypted data.

## Requirements
- Go v1.16.0 or higher
- RSA Public and Private Key in base64 format
