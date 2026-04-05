package hikws

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

var (
	hikFixedKey, _ = hex.DecodeString("1234567891234567123456789123456712345678912345671234567891234567")
	hikFixedIV, _  = hex.DecodeString("12345678912345671234567891234567")
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func aesEncryptCBC(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedData := pkcs7Pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(paddedData))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, nil
}

// GenerateClientIVKey generates the client IV and key based on timestamp
func GenerateClientIVKey() (string, string, error) {
	nowMs := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
	plaintext := []byte(nowMs)

	// Since AES-256 uses 32 bytes and the fixed key is 32 bytes
	ivBytes, err := aesEncryptCBC(plaintext, hikFixedKey, hikFixedIV)
	if err != nil {
		return "", "", err
	}
	iv := hex.EncodeToString(ivBytes)
	for len(iv) < 64 {
		iv += iv
	}

	keyBytes, err := aesEncryptCBC(plaintext, hikFixedKey, hikFixedIV)
	if err != nil {
		return "", "", err
	}
	key := hex.EncodeToString(keyBytes)
	for len(key) < 64 {
		key += key
	}

	return iv, key, nil
}

// GenerateRealplayKey generates the key field for realplay using RSA encryption with custom JS padding
func GenerateRealplayKey(iv, key, pkdHex string) (string, error) {
	plaintext := fmt.Sprintf("%s:%s", iv, key)
	pkdBytes, err := hex.DecodeString(pkdHex)
	if err != nil {
		return "", err
	}

	keyLen := len(pkdBytes)
	nInt := new(big.Int).SetBytes(pkdBytes)

	msgUtf8 := []byte(plaintext)
	block := make([]byte, keyLen)

	t := keyLen
	i := len(msgUtf8) - 1

	for i >= 0 {
		t--
		block[t] = msgUtf8[i]
		i--
	}

	// 0x00 separator
	t--
	block[t] = 0

	// Random non-zero padding
	for t > 2 {
		t--
		r := make([]byte, 1)
		for {
			_, err := rand.Read(r)
			if err != nil {
				return "", err
			}
			if r[0] != 0 {
				break
			}
		}
		block[t] = r[0]
	}

	if t > 1 {
		block[1] = 0x02
	}
	if t > 0 {
		block[0] = 0x00
	}

	mInt := new(big.Int).SetBytes(block)
	eInt := big.NewInt(65537)

	cInt := new(big.Int).Exp(mInt, eInt, nInt)

	cBytes := cInt.Bytes()

	// Ensure padding to key length
	if len(cBytes) < keyLen {
		padded := make([]byte, keyLen)
		copy(padded[keyLen-len(cBytes):], cBytes)
		cBytes = padded
	}

	return hex.EncodeToString(cBytes), nil
}

// GenerateAuthorization generates the authorization field
func GenerateAuthorization(randStr, password, keyHex, ivHex string) (string, error) {
	plaintext := fmt.Sprintf("%s:%s", randStr, password)
	keyBytes, _ := hex.DecodeString(keyHex[:64])
	ivBytes, _ := hex.DecodeString(ivHex[:32])

	if len(keyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded, keyBytes)
		keyBytes = padded
	}

	encBytes, err := aesEncryptCBC([]byte(plaintext), keyBytes[:32], ivBytes[:16])
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(encBytes), nil
}

// GenerateToken generates the token field using AES encrypting the SHA256 of the URL
func GenerateToken(urlStr, keyHex, ivHex string) (string, error) {
	h := sha256.New()
	h.Write([]byte(urlStr))
	urlHash := hex.EncodeToString(h.Sum(nil))

	keyBytes, _ := hex.DecodeString(keyHex[:64])
	ivBytes, _ := hex.DecodeString(ivHex[:32])

	if len(keyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded, keyBytes)
		keyBytes = padded
	}

	encBytes, err := aesEncryptCBC([]byte(urlHash), keyBytes[:32], ivBytes[:16])
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(encBytes), nil
}
