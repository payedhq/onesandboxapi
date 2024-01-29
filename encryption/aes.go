package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// EncryptAES encrypts plaintext using AES encryption in CBC mode
func EncryptAES(plaintext, key, iv string) (string, error) {
	keyBytes := []byte(key)
	ivBytes := []byte(iv)
	plaintextBytes := []byte(plaintext)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	plaintextBytes = padPKCS7(plaintextBytes, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, ivBytes)
	ciphertext := make([]byte, len(plaintextBytes))
	mode.CryptBlocks(ciphertext, plaintextBytes)
	ciphertextHex := hex.EncodeToString(ciphertext)
	return ciphertextHex, nil
}

// DecryptAES decrypts ciphertext using AES decryption in CBC mode
func DecryptAES(ciphertext, key, iv string) (string, error) {
	keyBytes := []byte(key)
	ivBytes := []byte(iv)
	ciphertextBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Create AES block cipher
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Create cipher block mode with CBC
	mode := cipher.NewCBCDecrypter(block, ivBytes)

	// Decrypt ciphertext
	plaintext := make([]byte, len(ciphertextBytes))
	mode.CryptBlocks(plaintext, ciphertextBytes)

	// Unpad plaintext
	plaintext, err = unpadPKCS7(plaintext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// padPKCS7 pads the input to the specified block size using PKCS#7 padding
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

// unpadPKCS7 removes PKCS#7 padding from the input
func unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) {
		return nil, errors.New("invalid padding")
	}

	return data[:len(data)-padding], nil
}
