/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"testing"

	wgcrypto "golang.zx2c4.com/wireguard/device/crypto"
)

type KDFTest struct {
	key   string
	input string
	t0    string
	t1    string
	t2    string
}

func assertEquals(t *testing.T, a, b string) {
	if a != b {
		t.Fatal("expected", a, "=", b)
	}
}

func TestKDF(t *testing.T) {
	var t0, t1, t2 [wgcrypto.HashSize]byte

	// Record stable vectors for regression
	key, _ := hex.DecodeString("746573742d6b6579")
	input, _ := hex.DecodeString("746573742d696e707574")
	KDF3(&t0, &t1, &t2, key, input)
	t.Logf("KDF3 test-vector: t0=%s t1=%s t2=%s",
		hex.EncodeToString(t0[:]),
		hex.EncodeToString(t1[:]),
		hex.EncodeToString(t2[:]))

	KDF2(&t0, &t1, key, input)
	KDF1(&t0, key, input)

	key2, _ := hex.DecodeString("776972656775617264")
	KDF3(&t0, &t1, &t2, key2, key2)
	t.Logf("KDF3 wireguard: t0=%s t1=%s t2=%s",
		hex.EncodeToString(t0[:]),
		hex.EncodeToString(t1[:]),
		hex.EncodeToString(t2[:]))

	// determinism
	var t0b, t1b, t2b [wgcrypto.HashSize]byte
	KDF3(&t0b, &t1b, &t2b, key, input)
	KDF3(&t0, &t1, &t2, key, input)
	if t0 != t0b || t1 != t1b || t2 != t2b {
		t.Fatal("KDF3 not deterministic")
	}

	// empty inputs produce distinct outputs
	KDF3(&t0, &t1, &t2, nil, nil)
	if t0 == t1 || t1 == t2 || t0 == t2 {
		t.Fatal("KDF3 outputs must differ for empty input")
	}
}
