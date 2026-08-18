/* SPDX-License-Identifier: MIT */

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	gmsmrand "github.com/emmansun/gmsm/rand"
	wgcrypto "golang.zx2c4.com/wireguard/device/crypto"
)

func cmdGenKey() error {
	sk, err := wgcrypto.NewPrivateKey()
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(sk[:]))
	return nil
}

func cmdGenPSK() error {
	var psk [wgcrypto.PresharedKeySize]byte
	if _, err := io.ReadFull(gmsmrand.Reader, psk[:]); err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(psk[:]))
	return nil
}

func cmdPubKey(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	hexKey := strings.TrimSpace(string(data))
	skBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("invalid private key hex: %w", err)
	}
	priv, err := wgcrypto.LoadPrivateKeyFromBytes(skBytes)
	if err != nil {
		return err
	}
	pub, err := (&priv).PublicKey()
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(pub[:]))
	return nil
}

func readPrivateKeyArg(arg string) ([]byte, error) {
	if arg == "" {
		return io.ReadAll(os.Stdin)
	}
	return []byte(arg), nil
}
