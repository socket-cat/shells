// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package ssh

import (
	"net"
	"testing"
)

func TestIsWindows(t *testing.T) {
	for banner, want := range map[string]bool{
		"SSH-2.0-OpenSSH_for_Windows_9.5\r\n": true,
		"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n":  false,
		"":                                    false,
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Write([]byte(banner))
				c.Close()
			}
		}()
		if got := IsWindows("127.0.0.1", ln.Addr().(*net.TCPAddr).Port); got != want {
			t.Errorf("IsWindows(%q) = %v, want %v", banner, got, want)
		}
		ln.Close()
	}
}
