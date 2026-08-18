/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// TODO: replace these with actual standard windows error numbers from the win package
const (
	IpcErrorIO        = -int64(5)
	IpcErrorProtocol  = -int64(71)
	IpcErrorInvalid   = -int64(22)
	IpcErrorPortInUse = -int64(98)
	IpcErrorUnknown   = -int64(55)
)

type UAPIListener struct {
	listener net.Listener // unix socket listener
	connNew  chan net.Conn
	connErr  chan error
	kqueueFd int
	keventFd int
}

func (l *UAPIListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-l.connNew:
			return conn, nil

		case err := <-l.connErr:
			return nil, err
		}
	}
}

func (l *UAPIListener) Close() error {
	return l.listener.Close()
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

// uapiSDDLs are tried in order when creating the UAPI pipe. Every entry grants
// full access to LocalSystem and BUILTIN\Administrators only, and labels the
// pipe as high integrity; they differ solely in the owner they request.
//
// A process may only set an owner that its token carries, unless it holds
// SeRestorePrivilege. Running as the LocalSystem service (as WireGuard for
// Windows does) can request O:SY, while an elevated administrator cannot and
// would otherwise fail with ERROR_INVALID_OWNER.
var uapiSDDLs = []string{
	"O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)",
	"O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)",
	"D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)",
}

// UAPISecurityDescriptor is the preferred descriptor, kept for callers that
// embed this package and configure the pipe themselves.
var UAPISecurityDescriptor *windows.SECURITY_DESCRIPTOR

func init() {
	var err error
	UAPISecurityDescriptor, err = windows.SecurityDescriptorFromString(uapiSDDLs[0])
	if err != nil {
		panic(err)
	}
}

// ownerRejected reports whether err means the requested owner SID was refused,
// in which case a descriptor with a weaker owner is worth trying.
func ownerRejected(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_OWNER) ||
		errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}

func UAPIListen(name string) (net.Listener, error) {
	path := `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\` + name

	var listener net.Listener
	var err error
	for _, sddl := range uapiSDDLs {
		var sd *windows.SECURITY_DESCRIPTOR
		sd, err = windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			continue
		}
		listener, err = (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(path)
		if err == nil {
			break
		}
		if !ownerRejected(err) {
			return nil, err
		}
	}
	if listener == nil {
		return nil, err
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	go func(l *UAPIListener) {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				l.connErr <- err
				break
			}
			l.connNew <- conn
		}
	}(uapi)

	return uapi, nil
}
