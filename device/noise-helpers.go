/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"errors"

	wgcrypto "golang.zx2c4.com/wireguard/device/crypto"
)

func HMAC1(sum *[wgcrypto.HashSize]byte, key, in0 []byte) {
	wgcrypto.HMAC1(sum, key, in0)
}

func HMAC2(sum *[wgcrypto.HashSize]byte, key, in0, in1 []byte) {
	wgcrypto.HMAC2(sum, key, in0, in1)
}

func KDF1(t0 *[wgcrypto.HashSize]byte, key, input []byte) {
	wgcrypto.KDF1(t0, key, input)
}

func KDF2(t0, t1 *[wgcrypto.HashSize]byte, key, input []byte) {
	wgcrypto.KDF2(t0, t1, key, input)
}

func KDF3(t0, t1, t2 *[wgcrypto.HashSize]byte, key, input []byte) {
	wgcrypto.KDF3(t0, t1, t2, key, input)
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func newPrivateKey() (sk NoisePrivateKey, err error) {
	key, err := wgcrypto.NewPrivateKey()
	if err != nil {
		return sk, err
	}
	sk = NoisePrivateKey(key)
	return sk, nil
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey, err error) {
	key, err := (*wgcrypto.PrivateKey)(sk).PublicKey()
	if err != nil {
		return pk, err
	}
	pk = NoisePublicKey(key)
	return pk, nil
}

var errInvalidPublicKey = errors.New("invalid public key")

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [wgcrypto.HashSize]byte, err error) {
	return (*wgcrypto.PrivateKey)(sk).SharedSecret(wgcrypto.PublicKey(pk))
}
