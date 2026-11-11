package happ

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/kfwle/parser-go/assets"
)

func TestDecryptCrypt1to4(t *testing.T) {
	var file crypt1to4File
	if err := json.Unmarshal(assets.HappCrypt1to4, &file); err != nil {
		t.Fatal(err)
	}
	for index, linkPrefix := range []string{"crypt/", "crypt2/", "crypt3/", "crypt4/"} {
		block, _ := pem.Decode([]byte("-----BEGIN RSA PRIVATE KEY-----\n" + file.Keys[index].Key + "\n-----END RSA PRIVATE KEY-----\n"))
		if block == nil {
			t.Fatal("bad key")
		}
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		plaintext := "https://example.com/sub?token=" + strconv.Itoa(index)
		chunkSize := priv.PublicKey.Size() - 11
		var ciphertext []byte
		for start := 0; start < len(plaintext); start += chunkSize {
			end := start + chunkSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			chunk, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte(plaintext[start:end]))
			if err != nil {
				t.Fatal(err)
			}
			ciphertext = append(ciphertext, chunk...)
		}
		link := "happ://" + linkPrefix + base64.StdEncoding.EncodeToString(ciphertext)
		got, err := Decrypt(link)
		if err != nil {
			t.Fatalf("%s: %v", linkPrefix, err)
		}
		if got != plaintext {
			t.Fatalf("%s: got %q, want %q", linkPrefix, got, plaintext)
		}
	}
}

func TestDecryptCrypt5(t *testing.T) {
	var keys map[string]string
	if err := json.Unmarshal(assets.HappCrypt5, &keys); err != nil {
		t.Fatal(err)
	}
	var marker string
	for k := range keys {
		marker = k
		break
	}
	if len(marker) != 8 {
		t.Fatalf("unexpected marker %q", marker)
	}
	block, _ := pem.Decode([]byte("-----BEGIN PRIVATE KEY-----\n" + keys[marker] + "\n-----END PRIVATE KEY-----\n"))
	if block == nil {
		t.Fatal("bad PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	priv := parsed.(*rsa.PrivateKey)

	chachaKey := make([]byte, 32)
	if _, err := rand.Read(chachaKey); err != nil {
		t.Fatal(err)
	}
	chachaKeyB64 := base64.StdEncoding.EncodeToString(chachaKey)
	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte(swapPairs(chachaKeyB64)))
	if err != nil {
		t.Fatal(err)
	}
	encKeyB64 := base64.StdEncoding.EncodeToString(encKey)

	aead, err := chacha20poly1305.New(chachaKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce := "123456789012"
	finalURL := "https://example.com/sub?token=crypt5"
	finalB64 := base64.StdEncoding.EncodeToString([]byte(finalURL))
	intermediate := swapPairs(finalB64)
	sealed := aead.Seal(nil, []byte(nonce), []byte(intermediate), nil)
	urlB64 := base64.StdEncoding.EncodeToString(sealed)

	body := nonce + strconv.Itoa(len(urlB64)) + "x" + urlB64 + encKeyB64
	shuffled := marker[:4] + body + marker[4:]
	payload := blockPairSwap(shuffled)
	link := "happ://crypt5/" + payload

	got, err := DecryptURL(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != finalURL {
		t.Fatalf("got %q, want %q", got, finalURL)
	}
}

func TestSwapHelpers(t *testing.T) {
	original := "abcdefgh"
	swapped := swapPairs(original)
	if swapped != "badcfehg" {
		t.Fatalf("swapPairs: %q", swapped)
	}
	if swapPairs(swapped) != original {
		t.Fatal("swapPairs must be an involution")
	}
	blocked := blockPairSwap(original)
	if blocked != "cdabghef" {
		t.Fatalf("blockPairSwap: %q", blocked)
	}
	if blockPairSwap(blocked) != original {
		t.Fatal("blockPairSwap must be an involution")
	}
}

func TestUnknownType(t *testing.T) {
	if _, err := Decrypt("happ://crypt9/AAAA"); err == nil {
		t.Fatal("unknown crypt type must fail")
	}
	if _, err := Decrypt("https://example.com"); err == nil {
		t.Fatal("non-happ link must fail")
	}
}
