//go:build windows

/* SPDX-License-Identifier: MIT */

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

func uapiPath(iface string) string {
	return `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\` + iface
}

func uapiDial(iface string) (io.ReadWriteCloser, error) {
	return namedpipe.DialTimeout(uapiPath(iface), 5*time.Second)
}

func readUAPIResponse(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			return nil
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func uapiGet(iface string, w io.Writer) error {
	conn, err := uapiDial(iface)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("get=1\n\n")); err != nil {
		return err
	}
	return readUAPIResponse(conn, w)
}

func uapiSet(iface string, r io.Reader) error {
	conn, err := uapiDial(iface)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("set=1\n")); err != nil {
		return err
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("\n")); err != nil {
		return err
	}

	var buf strings.Builder
	if err := readUAPIResponse(conn, &buf); err != nil {
		return err
	}
	out := buf.String()
	if out != "" {
		fmt.Fprint(os.Stdout, out)
		if !strings.HasSuffix(out, "\n") {
			fmt.Fprintln(os.Stdout)
		}
	}
	if strings.Contains(out, "errno=") && !strings.Contains(out, "errno=0") {
		return fmt.Errorf("uapi set failed: %s", strings.TrimSpace(out))
	}
	return nil
}
