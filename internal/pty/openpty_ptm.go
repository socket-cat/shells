// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

//go:build openbsd || netbsd

package pty

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// ptmget mirrors struct ptmget (sys/ttycom.h): the kernel fills in both
// descriptors and their names. 40 bytes, as encoded in the ioctl number.
type ptmget struct {
	cfd, sfd int32
	cn, sn   [16]byte
}

// openPty allocates a pseudo-terminal pair via /dev/ptm: one ioctl returns
// the master and slave descriptors already open — the same mechanism
// openpty(3) uses on OpenBSD and NetBSD, no CGO needed.
func openPty() (master, slave *os.File, err error) {
	ptm, err := os.OpenFile("/dev/ptm", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("pty: open /dev/ptm: %w", err)
	}
	defer ptm.Close()
	var p ptmget
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, ptm.Fd(), ptmGetIoctl, uintptr(unsafe.Pointer(&p))); errno != 0 {
		return nil, nil, fmt.Errorf("pty: PTMGET ioctl: %w", errno)
	}
	return os.NewFile(uintptr(p.cfd), cstr(p.cn[:])), os.NewFile(uintptr(p.sfd), cstr(p.sn[:])), nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
