// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

//go:build freebsd

package pty

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// openPty allocates a pseudo-terminal pair on FreeBSD.
//
// FreeBSD's pts(4) does NOT implement TIOCSPTLCK (it is absent from
// sys/sys/ttycom.h — num 16 there is TIOCFLUSH, not the lock ioctl), so the
// slave is never locked and no unlockpt is needed. We prefer the Unix98
// /dev/ptmx path, then fall back to legacy BSD-style /dev/ptyXY devices for
// environments (e.g. jails) where /dev/ptmx is unavailable.
func openPty() (master, slave *os.File, err error) {
	// --- Unix98: /dev/ptmx + TIOCGPTN ---
	m, ptmxErr := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if ptmxErr == nil {
		var n uint32
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(),
			uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&n)))
		if errno == 0 {
			slaveName := fmt.Sprintf("/dev/pts/%d", n)
			s, slaveErr := os.OpenFile(slaveName, os.O_RDWR|syscall.O_NOCTTY, 0)
			if slaveErr == nil {
				return m, s, nil
			}
			m.Close()
			return nil, nil, fmt.Errorf(
				"pty: /dev/ptmx opened + TIOCGPTN ok (pts/%d) but slave %s: %s — ensure PTY module loaded: kldload pty",
				n, slaveName, slaveErr)
		}
		m.Close()
		return nil, nil, fmt.Errorf(
			"pty: /dev/ptmx opened but TIOCGPTN ioctl failed: %s", errno.Error())
	}

	// --- Legacy BSD-style: /dev/ptyXY (master) + /dev/ttyXY (slave) ---
	var lastBSDErr error
	for _, c1 := range "pqrstuvwxyzPQRST" {
		for _, c2 := range "0123456789abcdef" {
			masterName := fmt.Sprintf("/dev/pty%c%c", c1, c2)
			m, e := os.OpenFile(masterName, os.O_RDWR|syscall.O_NOCTTY, 0)
			if e != nil {
				lastBSDErr = e
				continue
			}
			slaveName := fmt.Sprintf("/dev/tty%c%c", c1, c2)
			s, e2 := os.OpenFile(slaveName, os.O_RDWR|syscall.O_NOCTTY, 0)
			if e2 != nil {
				m.Close()
				lastBSDErr = e2
				continue
			}
			return m, s, nil
		}
	}

	return nil, nil, fmt.Errorf(
		"pty: /dev/ptmx: %s; BSD-style /dev/pty*: %s — no PTY devices.\n"+
			"FIX: run 'kldload pty' (permanent: pty_load=\"YES\" in /boot/loader.conf)",
		ptmxErr, lastBSDErr)
}
