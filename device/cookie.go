/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/hmac"
	"sync"
	"time"

	gmsmrand "github.com/emmansun/gmsm/rand"
	wgcrypto "golang.zx2c4.com/wireguard/device/crypto"
)

type CookieChecker struct {
	sync.RWMutex
	mac1 struct {
		key [wgcrypto.HashSize]byte
	}
	mac2 struct {
		secret        [wgcrypto.HashSize]byte
		secretSet     time.Time
		encryptionKey [wgcrypto.AeadKeySize]byte
	}
}

type CookieGenerator struct {
	sync.RWMutex
	mac1 struct {
		key [wgcrypto.HashSize]byte
	}
	mac2 struct {
		cookie        [wgcrypto.MacSize]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [wgcrypto.MacSize]byte
		encryptionKey [wgcrypto.AeadKeySize]byte
	}
}

func hashKey(label string, pk NoisePublicKey, dst []byte) {
	h := wgcrypto.Sum256(append(append([]byte(nil), []byte(label)...), pk[:]...))
	copy(dst, h[:len(dst)])
}

func (st *CookieChecker) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	hashKey(WGLabelMAC1, pk, st.mac1.key[:])

	var full [wgcrypto.HashSize]byte
	hashKey(WGLabelCookie, pk, full[:])
	copy(st.mac2.encryptionKey[:], full[:wgcrypto.AeadKeySize])

	st.mac2.secretSet = time.Time{}
}

func (st *CookieChecker) CheckMAC1(msg []byte) bool {
	st.RLock()
	defer st.RUnlock()

	size := len(msg)
	smac2 := size - wgcrypto.MacSize
	smac1 := smac2 - wgcrypto.MacSize

	var mac1 [wgcrypto.MacSize]byte
	wgcrypto.MAC128(&mac1, st.mac1.key[:], msg[:smac1])

	return hmac.Equal(mac1[:], msg[smac1:smac2])
}

func (st *CookieChecker) CheckMAC2(msg, src []byte) bool {
	st.RLock()
	defer st.RUnlock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	var cookie [wgcrypto.MacSize]byte
	wgcrypto.MAC128(&cookie, st.mac2.secret[:], src)

	smac2 := len(msg) - wgcrypto.MacSize

	var mac2 [wgcrypto.MacSize]byte
	wgcrypto.MAC128(&mac2, cookie[:], msg[:smac2])

	return hmac.Equal(mac2[:], msg[smac2:])
}

func (st *CookieChecker) CreateReply(
	msg []byte,
	recv uint32,
	src []byte,
) (*MessageCookieReply, error) {
	st.RLock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		st.RUnlock()
		st.Lock()
		_, err := gmsmrand.Read(st.mac2.secret[:])
		if err != nil {
			st.Unlock()
			return nil, err
		}
		st.mac2.secretSet = time.Now()
		st.Unlock()
		st.RLock()
	}

	var cookie [wgcrypto.MacSize]byte
	wgcrypto.MAC128(&cookie, st.mac2.secret[:], src)

	size := len(msg)

	smac2 := size - wgcrypto.MacSize
	smac1 := smac2 - wgcrypto.MacSize

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType
	reply.Receiver = recv

	_, err := gmsmrand.Read(reply.Nonce[:])
	if err != nil {
		st.RUnlock()
		return nil, err
	}

	aead, err := wgcrypto.NewAEAD(st.mac2.encryptionKey[:])
	if err != nil {
		st.RUnlock()
		return nil, err
	}
	var gcmNonce [wgcrypto.AeadNonceSize]byte
	copy(gcmNonce[:], reply.Nonce[:wgcrypto.AeadNonceSize])
	aead.Seal(reply.Cookie[:0], gcmNonce[:], cookie[:], msg[smac1:smac2])

	st.RUnlock()

	return reply, nil
}

func (st *CookieGenerator) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	hashKey(WGLabelMAC1, pk, st.mac1.key[:])

	var full [wgcrypto.HashSize]byte
	hashKey(WGLabelCookie, pk, full[:])
	copy(st.mac2.encryptionKey[:], full[:wgcrypto.AeadKeySize])

	st.mac2.cookieSet = time.Time{}
}

func (st *CookieGenerator) ConsumeReply(msg *MessageCookieReply) bool {
	st.Lock()
	defer st.Unlock()

	if !st.mac2.hasLastMAC1 {
		return false
	}

	var cookie [wgcrypto.MacSize]byte

	aead, err := wgcrypto.NewAEAD(st.mac2.encryptionKey[:])
	if err != nil {
		return false
	}
	var gcmNonce [wgcrypto.AeadNonceSize]byte
	copy(gcmNonce[:], msg.Nonce[:wgcrypto.AeadNonceSize])
	_, err = aead.Open(cookie[:0], gcmNonce[:], msg.Cookie[:], st.mac2.lastMAC1[:])
	if err != nil {
		return false
	}

	st.mac2.cookieSet = time.Now()
	st.mac2.cookie = cookie
	return true
}

func (st *CookieGenerator) AddMacs(msg []byte) {
	size := len(msg)

	smac2 := size - wgcrypto.MacSize
	smac1 := smac2 - wgcrypto.MacSize

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	st.Lock()
	defer st.Unlock()

	wgcrypto.MAC128((*[wgcrypto.MacSize]byte)(mac1), st.mac1.key[:], msg[:smac1])
	copy(st.mac2.lastMAC1[:], mac1)
	st.mac2.hasLastMAC1 = true

	if time.Since(st.mac2.cookieSet) > CookieRefreshTime {
		return
	}

	wgcrypto.MAC128((*[wgcrypto.MacSize]byte)(mac2), st.mac2.cookie[:], msg[:smac2])
}
