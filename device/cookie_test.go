/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
)

func TestCookieMAC1(t *testing.T) {
	var (
		generator CookieGenerator
		checker   CookieChecker
	)

	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := sk.publicKey()
	if err != nil {
		t.Fatal(err)
	}

	generator.Init(pk)
	checker.Init(pk)

	src := []byte{192, 168, 13, 37, 10, 10, 10}

	checkMAC1 := func(msg []byte) {
		generator.AddMacs(msg)
		if !checker.CheckMAC1(msg) {
			t.Fatal("MAC1 generation/verification failed")
		}
		if checker.CheckMAC2(msg, src) {
			t.Fatal("MAC2 should not verify without cookie")
		}
	}

	// Build handshake-sized messages with trailing MAC slots
	makeMsg := func(payloadLen int) []byte {
		msg := make([]byte, payloadLen+32)
		for i := range payloadLen {
			msg[i] = byte(i)
		}
		return msg
	}

	checkMAC1(makeMsg(MessageInitiationSize - 32))
	checkMAC1(makeMsg(MessageResponseSize - 32))
	checkMAC1(makeMsg(64))

	replyMsg := makeMsg(MessageInitiationSize - 32)
	generator.AddMacs(replyMsg)
	reply, err := checker.CreateReply(replyMsg, 1377, src)
	if err != nil {
		t.Fatal("Failed to create cookie reply:", err)
	}
	if !generator.ConsumeReply(reply) {
		t.Fatal("Failed to consume cookie reply")
	}

	checkMAC2 := func(msg []byte) {
		generator.AddMacs(msg)

		if !checker.CheckMAC1(msg) {
			t.Fatal("MAC1 generation/verification failed")
		}
		if !checker.CheckMAC2(msg, src) {
			t.Fatal("MAC2 generation/verification failed")
		}

		msg[5] ^= 0x20

		if checker.CheckMAC1(msg) {
			t.Fatal("MAC1 should fail after tamper")
		}
		if checker.CheckMAC2(msg, src) {
			t.Fatal("MAC2 should fail after tamper")
		}

		msg[5] ^= 0x20

		srcBad1 := []byte{192, 168, 13, 37, 40, 1}
		if checker.CheckMAC2(msg, srcBad1) {
			t.Fatal("MAC2 should fail for wrong source")
		}
	}

	checkMAC2(makeMsg(128))
}
