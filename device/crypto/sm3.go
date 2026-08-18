/* SPDX-License-Identifier: MIT */

package crypto

import (
	"crypto/hmac"
	"hash"

	"github.com/emmansun/gmsm/sm3"
)

func newSM3() hash.Hash {
	return sm3.New()
}

func Sum256(data []byte) [HashSize]byte {
	return sm3.Sum(data)
}

func MixHash(dst, h *[HashSize]byte, data []byte) {
	hash := sm3.New()
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
}

func HMAC1(sum *[HashSize]byte, key, in0 []byte) {
	mac := hmac.New(newSM3, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[HashSize]byte, key, in0, in1 []byte) {
	mac := hmac.New(newSM3, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[HashSize]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[HashSize]byte, key, input []byte) {
	var prk [HashSize]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	zero(prk[:])
}

func KDF3(t0, t1, t2 *[HashSize]byte, key, input []byte) {
	var prk [HashSize]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	zero(prk[:])
}

// MAC128 computes a 128-bit keyed MAC as the first 16 bytes of HMAC-SM3.
func MAC128(sum *[MacSize]byte, key, input []byte) {
	var full [HashSize]byte
	HMAC1(&full, key, input)
	copy(sum[:], full[:MacSize])
}

func DeriveKey(dst *[AeadKeySize]byte, kdfOut *[HashSize]byte) {
	copy(dst[:], kdfOut[:AeadKeySize])
}

func zero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}
