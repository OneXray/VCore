// Independent primitive fixtures. Every key is synthetic test material.
// No network service, protocol decoder, or third-party source modification.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"

	"github.com/metacubex/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

func pattern(n, step, start int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*step + start)
	}
	return b
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	seed := pattern(64, 7, 1)
	kem, err := mlkem.NewDecapsulationKey768(seed)
	check(err)
	shared, ciphertext := kem.EncapsulationKey().Encapsulate()
	// Passing a previous JSON reproduces its random encapsulation exactly.
	if len(os.Args) == 2 {
		data, err := os.ReadFile(os.Args[1])
		check(err)
		var old map[string]json.RawMessage
		check(json.Unmarshal(data, &old))
		var value string
		check(json.Unmarshal(old["mlkem_ciphertext"], &value))
		ciphertext, err = hex.DecodeString(value)
		check(err)
		shared, err = kem.Decapsulate(ciphertext)
		check(err)
	}
	secret := pattern(32, 3, 5)
	x, err := ecdh.X25519().NewPrivateKey(secret)
	check(err)
	peer, err := ecdh.X25519().NewPrivateKey(pattern(32, 11, 9))
	check(err)
	xShared, err := x.ECDH(peer.PublicKey())
	check(err)
	context, material := pattern(16, 37, 255), pattern(96, 13, 7)
	derived := make([]byte, 32)
	blake3.DeriveKey(derived, string(context), material)
	block, err := aes.NewCipher(derived)
	check(err)
	gcm, err := cipher.NewGCM(block)
	check(err)
	chacha, err := chacha20poly1305.New(derived)
	check(err)
	plain := pattern(37, 17, 3)
	aad := []byte{23, 3, 3, 0, byte(len(plain) + 16)}
	var records []map[string]string
	for _, item := range []struct {
		name string
		aead cipher.AEAD
	}{{"aes256gcm", gcm}, {"chacha20poly1305", chacha}} {
		for _, last := range []byte{1, 2, 255} {
			nonce := make([]byte, 12)
			if last == 255 {
				for i := range nonce {
					nonce[i] = 255
				}
			} else {
				nonce[11] = last
			}
			records = append(records, map[string]string{
				"cipher": item.name, "context": hex.EncodeToString(context), "key": hex.EncodeToString(material),
				"nonce": hex.EncodeToString(nonce), "aad": hex.EncodeToString(aad), "plaintext": hex.EncodeToString(plain),
				"ciphertext": hex.EncodeToString(item.aead.Seal(nil, nonce, plain, aad)),
			})
		}
	}
	ctrKey := make([]byte, 32)
	blake3.DeriveKey(ctrKey, "VLESS", material)
	ctrBlock, err := aes.NewCipher(ctrKey)
	check(err)
	ctrOut := make([]byte, len(plain))
	cipher.NewCTR(ctrBlock, context).XORKeyStream(ctrOut, plain)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	check(encoder.Encode(map[string]any{
		"generator": "Go official crypto + metacubex/blake3; synthetic keys only", "go_version": runtime.Version(),
		"mlkem_seed": hex.EncodeToString(seed), "mlkem_public": hex.EncodeToString(kem.EncapsulationKey().Bytes()),
		"mlkem_ciphertext": hex.EncodeToString(ciphertext), "mlkem_shared": hex.EncodeToString(shared),
		"x25519_private": hex.EncodeToString(secret), "x25519_public": hex.EncodeToString(x.PublicKey().Bytes()),
		"x25519_peer": hex.EncodeToString(peer.PublicKey().Bytes()), "x25519_shared": hex.EncodeToString(xShared),
		"ctr_context": hex.EncodeToString(context), "ctr_key": hex.EncodeToString(material), "ctr_plaintext": hex.EncodeToString(plain), "ctr_ciphertext": hex.EncodeToString(ctrOut),
		"records": records,
	}))
}
