// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package wshandler

import (
	"testing"
	"time"

	"shells/internal/util"
)

func TestActivitySignalDue(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name string
		last time.Time
		now  time.Time
		want bool
	}{
		{"zero lastActSig", time.Time{}, base, true},
		{"500ms after", base, base.Add(500 * time.Millisecond), false},
		{"exactly 1s after", base, base.Add(time.Second), true},
		{"2s after", base, base.Add(2 * time.Second), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &attachState{lastActSig: tt.last}
			if got := activitySignalDue(st, tt.now); got != tt.want {
				t.Fatalf("activitySignalDue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRateAllowPerIPBurst(t *testing.T) {
	h := &Handler{connLimiter: util.NewRateLimiter()}
	window := time.Minute
	for i := 0; i < wsConnectsPerIP; i++ {
		if !h.connLimiter.Allow("1.2.3.4", wsConnectsPerIP, window) {
			t.Fatalf("attempt %d from same IP rejected before the limit", i+1)
		}
	}
	// Rejected attempts must not be recorded, so sustained floods keep
	// getting rejected without further memory growth (white-box proof in
	// internal/util/ratelimit_test.go).
	for i := 0; i < 50; i++ {
		if h.connLimiter.Allow("1.2.3.4", wsConnectsPerIP, window) {
			t.Fatalf("flood attempt %d admitted", i+1)
		}
	}
	if !h.connLimiter.Allow("5.6.7.8", wsConnectsPerIP, window) {
		t.Fatal("different IP affected by first IP's burst")
	}
}
