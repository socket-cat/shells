// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package util

import (
	"testing"
	"time"
)

func TestRateLimiterBurstAndCap(t *testing.T) {
	rl := NewRateLimiter()
	window := time.Minute
	const limit = 3

	for i := 0; i < limit; i++ {
		if !rl.Allow("1.2.3.4", limit, window) {
			t.Fatalf("attempt %d admitted beyond plan", i+1)
		}
	}
	if rl.Allow("1.2.3.4", limit, window) {
		t.Fatal("attempt beyond limit allowed")
	}
	// Rejected attempts are not recorded: the key's slice stays capped at
	// limit no matter how many times it is denied.
	for i := 0; i < 100; i++ {
		if rl.Allow("1.2.3.4", limit, window) {
			t.Fatalf("flood attempt %d admitted", i+1)
		}
	}
	if got := len(rl.limits["1.2.3.4"]); got != limit {
		t.Fatalf("rejected attempts grew the entry: %d timestamps stored, want %d", got, limit)
	}
	if !rl.Allow("5.6.7.8", limit, window) {
		t.Fatal("different key affected by first key's burst")
	}
}

func TestRateLimiterSweepsStaleEntries(t *testing.T) {
	rl := NewRateLimiter()
	window := time.Minute
	now := time.Now()
	rl.limits["stale-ip"] = []time.Time{now.Add(-2 * window)}
	rl.limits["fresh-ip"] = []time.Time{now.Add(-5 * time.Second)}
	// Force the sweep on the next call (it fires at most once a minute).
	rl.lastSweep = now.Add(-2 * time.Minute)

	if !rl.Allow("9.9.9.9", 30, window) {
		t.Fatal("fresh IP rejected unexpectedly")
	}
	if _, ok := rl.limits["stale-ip"]; ok {
		t.Fatal("stale IP entry not evicted (unbounded map growth)")
	}
	if _, ok := rl.limits["fresh-ip"]; !ok {
		t.Fatal("still-fresh IP entry wrongly evicted")
	}
	if _, ok := rl.limits["9.9.9.9"]; !ok {
		t.Fatal("admitted attempt not recorded")
	}
}

// A sweep run by a short-window caller keeps a longer window's history:
// update-apply's 2/hour must not reset whenever a 1/minute limit sweeps.
func TestRateLimiterSweepKeepsLongerWindows(t *testing.T) {
	rl := NewRateLimiter()
	now := time.Now()
	if !rl.Allow("hourly", 1, time.Hour) {
		t.Fatal("first hourly attempt rejected")
	}
	rl.limits["hourly"] = []time.Time{now.Add(-10 * time.Minute)}
	rl.lastSweep = now.Add(-2 * time.Minute)
	rl.Allow("minutely", 30, time.Minute)
	if rl.Allow("hourly", 1, time.Hour) {
		t.Fatal("the hourly limit was reset by a minute-window sweep")
	}
}
