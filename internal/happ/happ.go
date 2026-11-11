// Package happ decrypts happ://cryptN/... links without Python or external
// crypto libraries. crypt1-4 use RSA PKCS#1 v1.5, crypt5 uses RSA + ChaCha20-Poly1305.
package happ

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/kfwle/parser-go/assets"
	"github.com/kfwle/parser-go/internal/extract"
)

type crypt1to4File struct {
	Keys []struct {
		Name string `json:"name"`
		Bits int    `json:"bits"`
		Key  string `json:"key"`
	} `json:"keys"`
}

var (
	keysOnce sync.Once
	rsaKeys  []*rsa.PrivateKey
	rsaErr   error
	keys5    map[string]string
	keys5Err error
)

func loadKeys() {
	keysOnce.Do(func() {
		var file crypt1to4File
		if err := json.Unmarshal(assets.HappCrypt1to4, &file); err != nil {
			rsaErr = err
			return
		}
		for _, k := range file.Keys {
			block, _ := pem.Decode([]byte("-----BEGIN RSA PRIVATE KEY-----\n" + k.Key + "\n-----END RSA PRIVATE KEY-----\n"))
			if block == nil {
				rsaErr = fmt.Errorf("bad RSA key %q", k.Name)
				return
			}
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				rsaErr = fmt.Errorf("parse RSA key %q: %w", k.Name, err)
				return
			}
			rsaKeys = append(rsaKeys, key)
		}
		if err := json.Unmarshal(assets.HappCrypt5, &keys5); err != nil {
			keys5Err = err
		}
	})
}

// Decrypt decrypts a happ://crypt... link and returns the plaintext payload.
func Decrypt(link string) (string, error) {
	link = strings.TrimSpace(link)
	lower := strings.ToLower(link)
	if !strings.HasPrefix(lower, "happ://") {
		return "", fmt.Errorf("not a happ link")
	}
	path := link[len("happ://"):]
	switch {
	case strings.HasPrefix(path, "crypt5/"):
		return decryptCrypt5(path[len("crypt5/"):])
	case strings.HasPrefix(path, "crypt4/"):
		return decryptCrypt1to4(3, path[len("crypt4/"):])
	case strings.HasPrefix(path, "crypt3/"):
		return decryptCrypt1to4(2, path[len("crypt3/"):])
	case strings.HasPrefix(path, "crypt2/"):
		return decryptCrypt1to4(1, path[len("crypt2/"):])
	case strings.HasPrefix(path, "crypt/"):
		return decryptCrypt1to4(0, path[len("crypt/"):])
	}
	return "", fmt.Errorf("unknown happ crypt type")
}

// DecryptURL decrypts a link and returns the first http(s) URL inside.
func DecryptURL(link string) (string, error) {
	text, err := Decrypt(link)
	if err != nil {
		return "", err
	}
	urls := extract.FindURLs(text)
	if len(urls) == 0 {
		return "", fmt.Errorf("no URL in decrypted payload")
	}
	return urls[0], nil
}

func decryptCrypt1to4(index int, payload string) (string, error) {
	loadKeys()
	if rsaErr != nil {
		return "", rsaErr
	}
	if index < 0 || index >= len(rsaKeys) {
		return "", fmt.Errorf("crypt key %d not found", index)
	}
	key := rsaKeys[index]
	ciphertext, err := extract.DecodeBase64(payload)
	if err != nil {
		return "", fmt.Errorf("base64: %w", err)
	}
	size := key.Size()
	var out []byte
	for offset := 0; offset < len(ciphertext); offset += size {
		end := offset + size
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, key, ciphertext[offset:end])
		if err != nil {
			return "", fmt.Errorf("rsa: %w", err)
		}
		out = append(out, chunk...)
	}
	return string(out), nil
}

func decryptCrypt5(payload string) (string, error) {
	loadKeys()
	if keys5Err != nil {
		return "", keys5Err
	}
	shuffled := blockPairSwap(payload)
	if len(shuffled) < 8 {
		return "", fmt.Errorf("crypt5 payload too short")
	}
	marker := shuffled[:4] + shuffled[len(shuffled)-4:]
	body := shuffled[4 : len(shuffled)-4]
	if len(body) < 13 {
		return "", fmt.Errorf("crypt5 body too short")
	}
	nonceStr := body[:12]
	rest := body[12:]

	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return "", fmt.Errorf("crypt5 segment length missing")
	}
	segmentLen, err := strconv.Atoi(rest[:digits])
	if err != nil {
		return "", fmt.Errorf("crypt5 segment length: %w", err)
	}
	packed := rest[digits:]
	if len(packed) < 1+segmentLen {
		return "", fmt.Errorf("crypt5 segment truncated")
	}
	urlB64 := packed[1 : 1+segmentLen]
	encStr := packed[1+segmentLen:]

	keyB64, ok := keys5[marker]
	if !ok {
		return "", fmt.Errorf("no RSA key for marker %q", marker)
	}
	block, _ := pem.Decode([]byte("-----BEGIN PRIVATE KEY-----\n" + keyB64 + "\n-----END PRIVATE KEY-----\n"))
	if block == nil {
		return "", fmt.Errorf("bad crypt5 PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse crypt5 key: %w", err)
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("crypt5 key is not RSA")
	}
	cipherBytes, err := extract.DecodeBase64(encStr)
	if err != nil {
		return "", fmt.Errorf("crypt5 rsa base64: %w", err)
	}
	rsaPlain, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cipherBytes)
	if err != nil {
		return "", fmt.Errorf("crypt5 rsa: %w", err)
	}
	chachaKey, err := extract.DecodeBase64(string(swapPairsBytes(rsaPlain)))
	if err != nil {
		return "", fmt.Errorf("crypt5 chacha key: %w", err)
	}
	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		return "", fmt.Errorf("chacha init: %w", err)
	}
	if len(nonceStr) != aead.NonceSize() {
		return "", fmt.Errorf("crypt5 nonce size %d", len(nonceStr))
	}
	urlCipher, err := extract.DecodeBase64(urlB64)
	if err != nil {
		return "", fmt.Errorf("crypt5 url base64: %w", err)
	}
	intermediate, err := aead.Open(nil, []byte(nonceStr), urlCipher, nil)
	if err != nil {
		return "", fmt.Errorf("chacha decrypt: %w", err)
	}
	final, err := extract.DecodeBase64(string(swapPairsBytes(intermediate)))
	if err != nil {
		return "", fmt.Errorf("crypt5 final base64: %w", err)
	}
	return string(final), nil
}

// swapPairs swaps adjacent characters (Python swap_pairs).
func swapPairs(s string) string { return swapPairsBytes([]byte(s)) }

func swapPairsBytes(b []byte) string {
	out := make([]byte, len(b))
	copy(out, b)
	for i := 0; i+1 < len(out); i += 2 {
		out[i], out[i+1] = out[i+1], out[i]
	}
	return string(out)
}

// blockPairSwap swaps 2-byte blocks inside every 4-byte group. The operation is
// its own inverse, exactly like the original implementation.
func blockPairSwap(s string) string {
	b := []byte(s)
	full := len(b) - len(b)%4
	out := make([]byte, 0, len(b))
	for off := 0; off < full; off += 4 {
		out = append(out, b[off+2], b[off+3], b[off], b[off+1])
	}
	out = append(out, b[full:]...)
	return string(out)
}
