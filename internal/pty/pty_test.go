// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package pty

import (
	"strings"
	"sync"
	"testing"
	"time"
)

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

// waitOutput subscribes like session.Create (OnData, then OnExit) and returns
// the whole output once the exit callback ran.
func waitOutput(t *testing.T, term *Term, onData func()) string {
	t.Helper()
	var mu sync.Mutex
	var out strings.Builder
	term.OnData(func(b []byte) {
		mu.Lock()
		out.Write(b)
		mu.Unlock()
		onData()
	})
	exited := make(chan struct{})
	term.OnExit(func(int, string) { close(exited) })
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("exit callback never ran")
	}
	mu.Lock()
	defer mu.Unlock()
	return out.String()
}

// TestSubscribeAfterExit subscribes only once the child has written and
// exited (a 1 vCPU box under load): the output and the exit still arrive.
func TestSubscribeAfterExit(t *testing.T) {
	term, err := Spawn("echo", []string{"hi"}, nil, "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if out := waitOutput(t, term, func() {}); !strings.Contains(out, "hi") {
		t.Fatalf("output %q, want hi", out)
	}
}

// TestExitDrainsOutput keeps the subscriber busy while the child writes its
// last line and exits: that line is still read before the exit.
func TestExitDrainsOutput(t *testing.T) {
	term, err := Spawn("sh", []string{"-c", "echo first; sleep 0.05; echo last"}, nil, "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	busy := true
	out := waitOutput(t, term, func() {
		if busy {
			busy = false
			time.Sleep(200 * time.Millisecond)
		}
	})
	if !strings.Contains(out, "last") {
		t.Fatalf("output %q, want last", out)
	}
}

// TestExitWhileSlaveHeld leaves a job that escaped the hangup (setsid) holding
// the slave: no EIO comes, yet the exit goes out after drainWait, not when the
// job ends, with the output written before it.
func TestExitWhileSlaveHeld(t *testing.T) {
	term, err := Spawn("sh", []string{"-c", "setsid sleep 3 & sleep 0.1; echo x"}, nil, "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out := waitOutput(t, term, func() {})
	if d := time.Since(start); d > drainWait+time.Second {
		t.Fatalf("exit after %v, want about drainWait", d)
	}
	if !strings.Contains(out, "x") {
		t.Fatalf("output %q, want x", out)
	}
}
