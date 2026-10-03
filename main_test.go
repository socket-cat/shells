// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package main

import (
	"bytes"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"shells/internal/static"
)

// TestEmbeddedAssetsFresh fails when the embedded publicgz/ no longer matches
// public/ (edited frontend without `go generate`): the binary would ship
// stale assets.
func TestEmbeddedAssetsFresh(t *testing.T) {
	sub, err := fs.Sub(embedPublic, "publicgz")
	if err != nil {
		t.Fatal(err)
	}
	got, err := static.Unpack(sub)
	if err != nil {
		t.Fatal(err)
	}
	want := os.DirFS("public")
	n := 0
	err = fs.WalkDir(want, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		w, _ := fs.ReadFile(want, p)
		if g, err := fs.ReadFile(got, p); err != nil || !bytes.Equal(g, w) {
			t.Errorf("%s: embedded copy stale or missing — run `go generate .`", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files := len(got.(fstest.MapFS)); n == 0 || files != n {
		t.Errorf("embedded has %d files, public/ has %d — run `go generate .`", files, n)
	}
}

// TestTokenLogNoteRedacts asserts the startup-log token note names the source
// ($SHELLS_TOKEN) and never contains a token-like secret or auto-generated noise.
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
	if got := tokenLogNote("generated"); got != "" {
		t.Fatalf("tokenLogNote(generated) = %q, want empty", got)
	}
}
