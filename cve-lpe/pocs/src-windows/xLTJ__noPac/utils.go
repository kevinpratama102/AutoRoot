package main

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"unicode/utf16"
)

// generateRandomName creates a random computer name like "DESKTOP-XXXXXXXX"
func generateRandomName() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return "DESKTOP-" + string(b)
}

// generateRandomPassword creates a random 32-character password.
func generateRandomPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func encodeUTF16LE(s string) []byte {
	utf16Chars := utf16.Encode([]rune(s))
	b := make([]byte, len(utf16Chars)*2)
	for i, c := range utf16Chars {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}
