// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

//go:build darwin

package pty

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// openPty allocates a BSD-style PTY pair via /dev/ptmx using macOS-specific
// ioctls (TIOCPTYGRANT, TIOCPTYUNLK, TIOCPTYGNAME) — no CGO required.
func openPty() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("pty: open /dev/ptmx: %w", err)
	}

	// grantpt — set permissions on the slave device.
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(),
		uintptr(syscall.TIOCPTYGRANT), 0); errno != 0 {
		m.Close()
		return nil, nil, fmt.Errorf("pty: grantpt: %w", errno)
	}

	// unlockpt — unlock the slave for opening.
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(),
		uintptr(syscall.TIOCPTYUNLK), 0); errno != 0 {
		m.Close()
		return nil, nil, fmt.Errorf("pty: unlockpt: %w", errno)
	}

	// ptsname — retrieve the slave device path into a 128-byte buffer.
	var buf [128]byte
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(),
		uintptr(syscall.TIOCPTYGNAME), uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		m.Close()
		return nil, nil, fmt.Errorf("pty: ptsname: %w", errno)
	}

	n := clen(buf[:])
	if n == 0 {
		m.Close()
		return nil, nil, fmt.Errorf("pty: empty slave name")
	}
	slaveName := string(buf[:n])
	s, err := os.OpenFile(slaveName, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("pty: open %s: %w", slaveName, err)
	}

	return m, s, nil
}

func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}
