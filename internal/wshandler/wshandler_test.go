// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package wshandler

import (
	"testing"
	"time"
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
