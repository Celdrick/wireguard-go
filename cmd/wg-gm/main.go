/* SPDX-License-Identifier: MIT */

package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

const version = "0.1.0-gm"

func usage() {
	fmt.Fprintf(os.Stderr, `WireGuard-GM configuration utility v%s (%s-%s)

Usage: wg-gm <command> [arguments]

Commands:
  genkey              Generate a private SM2 key (32 bytes, hex)
  genpsk              Generate a preshared key (32 bytes, hex)
  pubkey              Derive public key from private key on stdin
  show <interface>    Show current WireGuard-GM configuration
  setconf <iface> <f> Apply configuration from file (use - for stdin)
  set <iface> k=v...  Apply individual settings
  help                Show this help

Examples:
  wg-gm genkey | tee privatekey | wg-gm pubkey > publickey
  wg-gm setconf wg0 peer-a.conf
  wg-gm show wg0

`, version, runtime.GOOS, runtime.GOARCH)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "help", "-h", "--help":
		usage()
	case "genkey":
		if err := cmdGenKey(); err != nil {
			fatal(err)
		}
	case "genpsk":
		if err := cmdGenPSK(); err != nil {
			fatal(err)
		}
	case "pubkey":
		if err := cmdPubKey(os.Stdin); err != nil {
			fatal(err)
		}
	case "show":
		if len(os.Args) != 3 {
			fatal(fmt.Errorf("usage: wg-gm show <interface>"))
		}
		if err := uapiGet(os.Args[2], os.Stdout); err != nil {
			fatal(err)
		}
	case "setconf":
		if len(os.Args) != 4 {
			fatal(fmt.Errorf("usage: wg-gm setconf <interface> <config-file|- >"))
		}
		var r io.Reader
		if os.Args[3] == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(os.Args[3])
			if err != nil {
				fatal(err)
			}
			defer f.Close()
			r = f
		}
		if err := uapiSet(os.Args[2], r); err != nil {
			fatal(err)
		}
	case "set":
		if len(os.Args) < 4 {
			fatal(fmt.Errorf("usage: wg-gm set <interface> <key=value> ..."))
		}
		iface := os.Args[2]
		lines := strings.Join(os.Args[3:], "\n")
		if err := uapiSet(iface, strings.NewReader(lines)); err != nil {
			fatal(err)
		}
	case "version", "--version":
		fmt.Printf("wg-gm v%s (%s-%s)\n", version, runtime.GOOS, runtime.GOARCH)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "wg-gm: %v\n", err)
	os.Exit(1)
}
