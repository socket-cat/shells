// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package pty

import "syscall"

// ptmGetIoctl is TIOCPTMGET = _IOR('t', 70, struct ptmget).
const ptmGetIoctl = syscall.TIOCPTMGET
