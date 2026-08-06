// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package release

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	ok := []string{"1.2.3", "v1.2.3", "0.0.0", "v10.20.30", "1.2.30"}
	for _, s := range ok {
		if _, _, _, err := parseVersion(s); err != nil {
			t.Errorf("parseVersion(%q) unexpected error: %v", s, err)
		}
	}
	bad := []string{"", "1.2", "1.2.3.4", "v", "1.x.3", "-1.2.3", "1.2.3-beta", "a.b.c", "1.02.3"}
	for _, s := range bad {
		if _, _, _, err := parseVersion(s); err == nil {
			t.Errorf("parseVersion(%q) expected error, got none", s)
		}
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.2.3", "1.2.4", true},
		{"1.2.4", "1.2.3", false},
		{"1.2.3", "1.2.3", false},
		{"1.2.3", "1.3.0", true},
		{"2.0.0", "1.9.9", false},
		{"v1.2.3", "v1.2.4", true},
		{"1.0.1", "1.2.0", true},
	}
	for _, c := range cases {
		got, err := versionLess(c.a, c.b)
		if err != nil {
			t.Errorf("versionLess(%q,%q) error: %v", c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("versionLess(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestParseManifest(t *testing.T) {
	raw := []byte("# shells 1.2.46\n" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  shells-linux-amd64\n" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  shells-darwin-arm64\n" +
		"\n# comment line should be ignored\n")
	m, err := parseManifest(raw)
	if err != nil {
		t.Fatalf("parseManifest error: %v", err)
	}
	if m.version != "1.2.46" {
		t.Errorf("version = %q, want 1.2.46", m.version)
	}
	if len(m.digests) != 2 {
		t.Errorf("digests = %d, want 2", len(m.digests))
	}
	if m.digests["shells-linux-amd64"] == "" {
		t.Errorf("missing linux/amd64 digest")
	}

	bad := [][]byte{
		[]byte("no header here"),
		[]byte("# shells 1.2.3\nshort  shells-x"),
		[]byte("# shells 1.2.3\n" + "zz  shells-x"),
		[]byte("# shells 1.2.3\n" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  a\n" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  b\n" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  b\n"),
	}
	for _, b := range bad {
		if _, err := parseManifest(b); err == nil {
			t.Errorf("parseManifest expected error for input %q", string(b))
		}
	}
}

func TestInitKeys(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(Fingerprints()) != 2 {
		t.Errorf("expected 2 fingerprints, got %d", len(Fingerprints()))
	}
}
