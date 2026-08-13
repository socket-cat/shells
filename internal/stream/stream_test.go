// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat) <ragull@socket.cat>

package stream

import "testing"

// TestParserParseCleanBoundary checks that Parse reports the length of the
// leading prefix ending on a clean (ground-state) boundary, feeding chunks
// exactly like the session's OnData callback does.
func TestParserParseCleanBoundary(t *testing.T) {
	tests := []struct {
		name      string
		chunks    []string
		wantClean []int // expected returned clean length per Parse call
		wantTitle string
		wantMode  string
		wantIsSet bool
	}{
		{
			name:      "plain text",
			chunks:    []string{"hello"},
			wantClean: []int{5},
		},
		{
			name:      "complete osc title",
			chunks:    []string{"\x1b]0;title\x07"},
			wantClean: []int{10},
			wantTitle: "title",
		},
		{
			name:      "osc split across chunks",
			chunks:    []string{"\x1b]0;ti", "tle\x07"},
			wantClean: []int{0, 4},
			wantTitle: "title",
		},
		{
			name:      "csi decset split across chunks",
			chunks:    []string{"\x1b[?2", "004h"},
			wantClean: []int{0, 4},
			wantMode:  "2004",
			wantIsSet: true,
		},
		{
			name:      "clean text with trailing partial escape",
			chunks:    []string{"abc\x1b["},
			wantClean: []int{3},
		},
		{
			name:      "dsr response falls back to ground",
			chunks:    []string{"\x1b[?2027;0$y"},
			wantClean: []int{11},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotTitle string
			var gotMode string
			var gotIsSet bool
			p := New(
				func(mode string, isSet bool) {
					gotMode = mode
					gotIsSet = isSet
				},
				func(title string) {
					gotTitle = title
				},
			)
			for i, chunk := range tt.chunks {
				got := p.Parse([]byte(chunk))
				if got != tt.wantClean[i] {
					t.Fatalf("Parse(%q) (call %d) = %d, want %d", chunk, i+1, got, tt.wantClean[i])
				}
			}
			if gotTitle != tt.wantTitle {
				t.Errorf("title = %q, want %q", gotTitle, tt.wantTitle)
			}
			if gotMode != tt.wantMode {
				t.Errorf("mode = %q, want %q", gotMode, tt.wantMode)
			}
			if gotIsSet != tt.wantIsSet {
				t.Errorf("isSet = %v, want %v", gotIsSet, tt.wantIsSet)
			}
		})
	}
}
