package hikws

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestGenerateClientIVKey(t *testing.T) {
	iv, key, err := GenerateClientIVKey()
	if err != nil {
		t.Fatal(err)
	}
	// The JS/Python reference doubles the value until it reaches 64 hex chars.
	if len(iv) < 64 || len(key) < 64 {
		t.Fatalf("iv/key too short: %d/%d", len(iv), len(key))
	}
	if _, err := hex.DecodeString(iv); err != nil {
		t.Errorf("iv is not hex: %v", err)
	}
	if _, err := hex.DecodeString(key); err != nil {
		t.Errorf("key is not hex: %v", err)
	}
}

// TestGenerateRealplayKey decrypts the produced ciphertext with the matching
// RSA private key and checks the custom PKCS#1 v1.5 block the Hikvision JS
// builds: 00 02 <non-zero padding> 00 <iv:key>.
func TestGenerateRealplayKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkd := hex.EncodeToString(priv.N.Bytes())

	iv, key, err := GenerateClientIVKey()
	if err != nil {
		t.Fatal(err)
	}
	if priv.E != 65537 {
		t.Fatalf("unexpected exponent %d (client hardcodes 65537)", priv.E)
	}

	ctHex, err := GenerateRealplayKey(iv, key, pkd)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := hex.DecodeString(ctHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len(priv.N.Bytes()) {
		t.Fatalf("ciphertext = %d bytes, want %d (modulus size)", len(ct), len(priv.N.Bytes()))
	}

	// m = c^d mod n, left-padded back to the modulus size.
	m := new(big.Int).Exp(new(big.Int).SetBytes(ct), priv.D, priv.N).Bytes()
	block := make([]byte, len(ct))
	copy(block[len(block)-len(m):], m)

	if block[0] != 0x00 || block[1] != 0x02 {
		t.Fatalf("bad padding prefix %02x %02x", block[0], block[1])
	}
	sep := bytes.IndexByte(block[2:], 0x00)
	if sep < 8 {
		t.Fatalf("padding separator at %d (too short)", sep)
	}
	if got, want := string(block[2+sep+1:]), iv+":"+key; got != want {
		t.Errorf("plaintext = %q, want %q", got, want)
	}
}

// aesDecryptCBC is the test-side inverse of the client's AES-256-CBC helper.
func aesDecryptCBC(t *testing.T, ctHex, keyHex, ivHex string) string {
	t.Helper()
	ct, err := hex.DecodeString(ctHex)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := hex.DecodeString(keyHex[:64])
	iv, _ := hex.DecodeString(ivHex[:32])
	block, err := aes.NewCipher(k[:32])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv[:16]).CryptBlocks(out, ct)
	// strip PKCS#7 padding
	pad := int(out[len(out)-1])
	if pad <= 0 || pad > len(out) {
		t.Fatalf("bad padding %d", pad)
	}
	return string(out[:len(out)-pad])
}

func TestGenerateAuthorizationAndToken(t *testing.T) {
	iv, key, err := GenerateClientIVKey()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := GenerateAuthorization("randval", "secret", key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if got := aesDecryptCBC(t, auth, key, iv); got != "randval:secret" {
		t.Errorf("authorization plaintext = %q, want %q", got, "randval:secret")
	}

	url := "ws://127.0.0.1:559/openUrl/tok"
	tok, err := GenerateToken(url, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(url))
	if got, want := aesDecryptCBC(t, tok, key, iv), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("token plaintext = %q, want sha256 hex %q", got, want)
	}
}
