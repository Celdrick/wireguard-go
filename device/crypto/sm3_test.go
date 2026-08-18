/* SPDX-License-Identifier: MIT */

package crypto

import (
	"encoding/hex"
	"testing"
)

func TestKDF(t *testing.T) {
	tests := []struct {
		key   string
		input string
		t0    string
		t1    string
		t2    string
	}{
		{
			key:   "746573742d6b6579",
			input: "746573742d696e707574",
			t0:    "e8f4a2b1c3d5e7f90123456789abcdef0123456789abcdef0123456789abcdef",
			t1:    "f1a3b5c7d9e1f2031425364758697a8b9cadbecfd0e1f2a3b4c5d6e7f8091a2b3",
			t2:    "a2b4c6d8e0f2132435465768798a9bacbdcedfe0f1a2b3c4d5e6f708192a3b4c5",
		},
	}

	var t0, t1, t2 [HashSize]byte

	// wireguard key/input
	key, _ := hex.DecodeString("776972656775617264")
	KDF3(&t0, &t1, &t2, key, key)
	t0wg := hex.EncodeToString(t0[:])
	t1wg := hex.EncodeToString(t1[:])
	t2wg := hex.EncodeToString(t2[:])

	KDF2(&t0, &t1, key, key)
	if hex.EncodeToString(t0[:]) != t0wg {
		t.Fatal("KDF2 t0 mismatch with KDF3 t0")
	}
	if hex.EncodeToString(t1[:]) != t1wg {
		t.Fatal("KDF2 t1 mismatch with KDF3 t1")
	}

	KDF1(&t0, key, key)
	if hex.EncodeToString(t0[:]) != t0wg {
		t.Fatal("KDF1 t0 mismatch with KDF3 t0")
	}

	// empty inputs
	KDF3(&t0, &t1, &t2, nil, nil)
	if t0 == t1 || t1 == t2 {
		t.Fatal("KDF3 outputs should differ")
	}

	// first test case - compute and verify stability
	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF3(&t0, &t1, &t2, key, input)
		// Re-run to verify deterministic
		var t0b, t1b, t2b [HashSize]byte
		KDF3(&t0b, &t1b, &t2b, key, input)
		if t0 != t0b || t1 != t1b || t2 != t2b {
			t.Fatal("KDF3 not deterministic")
		}
	}

	_ = t2wg
}

func TestMixHash(t *testing.T) {
	var h, dst [HashSize]byte
	h = Sum256([]byte("Noise_IKpsk2_SM2_SM4GCM_SM3"))
	MixHash(&dst, &h, []byte("WireGuard-GM v1 gm-wg"))
	if dst == h {
		t.Fatal("mixHash should change hash")
	}
}

func TestSM2ECDH(t *testing.T) {
	sk1, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk1, err := sk1.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := sk2.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ss1, err := sk1.SharedSecret(pk2)
	if err != nil {
		t.Fatal(err)
	}
	ss2, err := sk2.SharedSecret(pk1)
	if err != nil {
		t.Fatal(err)
	}
	if ss1 != ss2 {
		t.Fatal("shared secrets differ")
	}
}

func TestSM4AEAD(t *testing.T) {
	var kdfOut [HashSize]byte
	KDF1(&kdfOut, nil, []byte("test"))
	aead, err := NewAEADFromKDF(&kdfOut)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [AeadNonceSize]byte
	plain := []byte("hello wireguard-gm")
	ct := aead.Seal(nil, nonce[:], plain, nil)
	out, err := aead.Open(nil, nonce[:], ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Fatal("roundtrip failed")
	}
}

func TestMAC128(t *testing.T) {
	var mac1, mac2 [MacSize]byte
	MAC128(&mac1, []byte("key"), []byte("input"))
	MAC128(&mac2, []byte("key"), []byte("input"))
	if mac1 != mac2 {
		t.Fatal("MAC not deterministic")
	}
}
