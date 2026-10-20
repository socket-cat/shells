// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package pty

import "testing"

// TestResizeRacesExit resizes while the child exits and the waiter closes the
// master: under -race it must report nothing, and once closed every ioctl
// must just error.
func TestResizeRacesExit(t *testing.T) {
	for range 20 {
		term, err := Spawn("true", nil, nil, "", 80, 24)
		if err != nil {
			t.Fatal(err)
		}
		for term.Resize(100, 30) == nil {
			_ = term.SignalWinch()
		}
		if term.SignalWinch() == nil {
			t.Fatal("ioctl on a closed master succeeded")
		}
	}
}
