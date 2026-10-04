// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package main

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"shells/internal/assets"
	"shells/internal/static"
)

// TestEmbeddedAssetsFresh fails when the embedded publicgz/ no longer matches
// the file set built from public/ (edited frontend without `go generate`):
// the binary would ship stale assets.
func TestEmbeddedAssetsFresh(t *testing.T) {
	sub, err := fs.Sub(embedPublic, "publicgz")
	if err != nil {
		t.Fatal(err)
	}
	got, err := static.Unpack(sub)
	if err != nil {
		t.Fatal(err)
	}
	want, err := assets.Build("public")
	if err != nil {
		t.Fatal(err)
	}
	for p, w := range want {
		if g, err := fs.ReadFile(got, p); err != nil || !bytes.Equal(g, w) {
			t.Errorf("%s: embedded copy stale or missing — run `go generate .`", p)
		}
	}
	if files := len(got.(fstest.MapFS)); len(want) == 0 || files != len(want) {
		t.Errorf("embedded has %d files, want %d — run `go generate .`", files, len(want))
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

// TestDropHandshakeEOF: probe-induced handshake EOFs are dropped, real
// handshake failures and other server errors pass through unchanged.
func TestDropHandshakeEOF(t *testing.T) {
	var buf bytes.Buffer
	w := dropHandshakeEOF{&buf}
	drop := "2026/10/03 23:18:11 http: TLS handshake error from 127.0.0.1:43094: EOF\n"
	keep := []string{
		"2026/10/03 23:18:12 http: TLS handshake error from 10.0.0.5:5000: remote error: tls: bad certificate\n",
		"2026/10/03 23:18:13 http: TLS handshake error from 10.0.0.5:5001: tls: client offered only unsupported versions: []\n",
		"2026/10/03 23:18:14 http: panic serving 10.0.0.5:5002: boom\n",
	}
	for _, l := range append([]string{drop}, keep...) {
		if n, err := w.Write([]byte(l)); n != len(l) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", l, n, err)
		}
	}
	if got, want := buf.String(), strings.Join(keep, ""); got != want {
		t.Fatalf("filtered output:\n%s\nwant:\n%s", got, want)
	}
}
