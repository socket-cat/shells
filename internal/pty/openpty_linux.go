// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

//go:build linux

package pty

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// openPty allocates a Unix98 PTY pair (/dev/ptmx master + /dev/pts/N slave)
// using ioctl calls directly — no CGO, no external libraries.
func openPty() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("pty: open /dev/ptmx: %w", err)
	}

	// unlockpt — clear the lock on the slave device.
	var unlock int32 = 0
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(),
		uintptr(syscall.TIOCSPTLCK), uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		m.Close()
		return nil, nil, fmt.Errorf("pty: unlockpt: %w", errno)
	}

	// ptsname — get the slave device number.
	var n uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(),
		uintptr(syscall.TIOCGPTN), uintptr(unsafe.Pointer(&n))); errno != 0 {
		m.Close()
		return nil, nil, fmt.Errorf("pty: ptsname: %w", errno)
	}

	slaveName := fmt.Sprintf("/dev/pts/%d", n)
	s, err := os.OpenFile(slaveName, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("pty: open %s: %w", slaveName, err)
	}

	return m, s, nil
}
