// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package main

import (
	"strings"
	"testing"
)

// TestTokenLogNoteRedacts asserts the startup-log token note names the source
// ($SHELLS_TOKEN / auto-generated) and never contains a token-like secret.
// The redaction is structural: no code path feeds cfg.AppToken into the
// message at all, so any 8+ hex-char candidate must stay absent.
func TestTokenLogNoteRedacts(t *testing.T) {
	token := "deadbeef01deadbeef02" // would-be AppToken prefix under the old log
	for _, src := range []string{"env", "generated", ""} {
		note := tokenLogNote(src)
		if strings.Contains(note, token) {
			t.Fatalf("note for %q leaks token substring: %q", src, note)
		}
	}

	if got, want := tokenLogNote("env"), "(auth token from $SHELLS_TOKEN)"; got != want {
		t.Fatalf("tokenLogNote(env) = %q, want %q", got, want)
	}
	if got, want := tokenLogNote("generated"),
		"(auth token auto-generated this launch — set $SHELLS_TOKEN to pin one)"; got != want {
		t.Fatalf("tokenLogNote(generated) = %q, want %q", got, want)
	}
}
