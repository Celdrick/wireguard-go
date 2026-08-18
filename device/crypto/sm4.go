/* SPDX-License-Identifier: MIT */

package crypto

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

func NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := sm4.NewCipher(key[:AeadKeySize])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func NewAEADFromKDF(kdfOut *[HashSize]byte) (cipher.AEAD, error) {
	var key [AeadKeySize]byte
	DeriveKey(&key, kdfOut)
	return NewAEAD(key[:])
}
