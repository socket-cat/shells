// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package pty

// ptmGetIoctl is PTMGET = _IOR('t', 1, struct ptmget) from OpenBSD's
// sys/ttycom.h (absent from Go's syscall package).
const ptmGetIoctl = 0x40287401
