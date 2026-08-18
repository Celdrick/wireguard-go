/* SPDX-License-Identifier: MIT */

package crypto

import (
	"errors"
	"io"

	"github.com/emmansun/gmsm/ecdh"
	gmsmrand "github.com/emmansun/gmsm/rand"
)

var curve = ecdh.P256()

var ErrInvalidPublicKey = errors.New("invalid public key")

type PrivateKey [PrivateKeySize]byte
type PublicKey [PublicKeySize]byte
type PresharedKey [PresharedKeySize]byte

func NewPrivateKey() (PrivateKey, error) {
	priv, err := curve.GenerateKey(gmsmrand.Reader)
	if err != nil {
		return PrivateKey{}, err
	}
	var sk PrivateKey
	copy(sk[:], priv.Bytes())
	return sk, nil
}

func (sk *PrivateKey) PublicKey() (PublicKey, error) {
	priv, err := curve.NewPrivateKey(sk[:])
	if err != nil {
		return PublicKey{}, err
	}
	pub := priv.PublicKey()
	var pk PublicKey
	copy(pk[:], pub.Bytes())
	return pk, nil
}

func (sk *PrivateKey) SharedSecret(pk PublicKey) ([HashSize]byte, error) {
	var ss [HashSize]byte
	priv, err := curve.NewPrivateKey(sk[:])
	if err != nil {
		return ss, err
	}
	remote, err := curve.NewPublicKey(pk[:])
	if err != nil {
		return ss, err
	}
	secret, err := priv.ECDH(remote)
	if err != nil {
		return ss, err
	}
	if len(secret) != HashSize {
		return ss, ErrInvalidPublicKey
	}
	copy(ss[:], secret)
	return ss, nil
}

func LoadPrivateKeyFromBytes(b []byte) (PrivateKey, error) {
	if len(b) != PrivateKeySize {
		return PrivateKey{}, errors.New("invalid private key size")
	}
	if _, err := curve.NewPrivateKey(b); err != nil {
		return PrivateKey{}, err
	}
	var sk PrivateKey
	copy(sk[:], b)
	return sk, nil
}

func LoadPublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != PublicKeySize {
		return PublicKey{}, errors.New("invalid public key size")
	}
	if _, err := curve.NewPublicKey(b); err != nil {
		return PublicKey{}, err
	}
	var pk PublicKey
	copy(pk[:], b)
	return pk, nil
}

func ReadRandom(b []byte) (int, error) {
	return io.ReadFull(gmsmrand.Reader, b)
}
