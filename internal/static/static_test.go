// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat) <ragull@socket.cat>

package static

import (
	"bytes"
	"image"
	"image/png"
	"math/rand/v2"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"shells/internal/branding"
)

func testFS() *fstest.MapFS {
	return &fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(`<!DOCTYPE html><html><head><title>{{APP_NAME}}</title></head><body></body></html>`)},
		"app.js":     &fstest.MapFile{Data: []byte(`console.log(1)`)},
	}
}

func newTestHandler(t *testing.T, accent string) *Handler {
	t.Helper()
	brand := branding.Load(filepath.Join(t.TempDir(), "branding.json"), "Test", accent)
	h, err := New(testFS(), "1.0.1-test", "", accent, "Test", brand)
	if err != nil {
		t.Fatalf("static.New: %v", err)
	}
	return h
}

func decodePNG(t *testing.T, body []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("png.Decode: %v", err)
	}
	return img
}

func TestGeneratedIconsServe(t *testing.T) {
	h := newTestHandler(t, "#fab283")

	for _, tt := range []struct {
		path string
		size int
	}{
		{"/apple-touch-icon.png", 180},
		{"/icon-192.png", 192},
		{"/icon-512.png", 512},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", tt.path, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: status %d, want 200", tt.path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
			t.Fatalf("%s: content-type %q, want image/png", tt.path, ct)
		}
		img := decodePNG(t, rec.Body.Bytes())
		if img.Bounds().Dx() != tt.size || img.Bounds().Dy() != tt.size {
			t.Fatalf("%s: bounds %v, want %dx%d", tt.path, img.Bounds(), tt.size, tt.size)
		}
	}
}

func TestGeneratedIconReflectsAccentChange(t *testing.T) {
	h := newTestHandler(t, "#fab283")

	outlineRed := func() uint8 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/icon-512.png", nil)
		h.ServeHTTP(rec, req)
		img := decodePNG(t, rec.Body.Bytes())
		r, _, _, _ := img.At(256, 52).RGBA()
		return uint8(r >> 8)
	}

	// Initial accent #fab283 → red channel 0xfa.
	if got := outlineRed(); got != 0xfa {
		t.Fatalf("initial accent: red = %02x, want fa", got)
	}

	// Update branding accent in-place; a fresh request must re-render.
	if err := h.brand.Set("Test", "#1234ab"); err != nil {
		t.Fatalf("brand.Set: %v", err)
	}
	if got := outlineRed(); got != 0x12 {
		t.Fatalf("after accent change: red = %02x, want 12", got)
	}

	// And it must be stable across requests (cache hit, same accent).
	if got := outlineRed(); got != 0x12 {
		t.Fatalf("cached re-render: red = %02x, want 12", got)
	}
}

func TestGeneratedIconUnknownPath(t *testing.T) {
	h := newTestHandler(t, "#fab283")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/icon-999.png", nil)
	h.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatalf("unknown icon path returned 200")
	}
}

// TestInjectSRIMatchesRegexSpec pins the hand-written SRI tag scanner (which
// replaced regexp) to the original regexes on the real index.html plus edge
// cases, and checks every local script/stylesheet actually gets integrity.
func TestInjectSRIMatchesRegexSpec(t *testing.T) {
	scriptSRI := regexp.MustCompile(`(<script\s[^>]*src=["']([^"']+)["'][^>]*?)(>)`)
	linkSRI := regexp.MustCompile(`(<link\s[^>]*href=["']([^"']+)["'][^>]*?)(>)`)
	h := &Handler{hashes: map[string]string{}}
	old := func(html string) string {
		html = scriptSRI.ReplaceAllStringFunc(html, func(m string) string {
			sub := scriptSRI.FindStringSubmatch(m)
			return h.injectAttr(sub[1], sub[2], sub[3])
		})
		return linkSRI.ReplaceAllStringFunc(html, func(m string) string {
			low := strings.ToLower(m)
			if strings.Contains(low, `rel="manifest"`) || strings.Contains(low, `rel="icon"`) || strings.Contains(low, `rel="apple-touch-icon"`) {
				return m
			}
			sub := linkSRI.FindStringSubmatch(m)
			return h.injectAttr(sub[1], sub[2], sub[3])
		})
	}
	page, err := os.ReadFile("../../public/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range regexp.MustCompile(`(?:src|href)="(/[^"?]+)`).FindAllStringSubmatch(string(page), -1) {
		h.hashes[u[1]] = "sha256-" + u[1]
	}
	for _, in := range []string{
		string(page),
		`<script src="/a.js"></script><script>x</script><script  src='/a.js?v=1' defer>`,
		`<scriptx src="/a.js"><SCRIPT src="/a.js"><script src=/a.js><script src="">`,
		`<link rel="stylesheet" href="/a.js"><link rel="icon" href="/a.js"><link href="/a.js" data-href="/b.js">`,
		`<script data-src="/a.js" src="/a.js">`, `<script src="/a.js"`, `<<script src="/a.js">>`,
		"<script\tsrc=\"/a.js\">\n<link\nhref=\"/a.js\">",
	} {
		h.hashes["/a.js"] = "sha256-a"
		if got, want := h.injectSRI(in), old(in); got != want {
			t.Errorf("injectSRI mismatch\n in: %.200q\ngot: %.200q\nwant: %.200q", in, got, want)
		}
	}
	toks := []string{"<script ", "<link ", "<", ">", "src=", "href=", `"`, "'", "/a.js", "x", " ", `rel="icon"`, "\n"}
	r := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for j := r.IntN(12); j >= 0; j-- {
			b.WriteString(toks[r.IntN(len(toks))])
		}
		if in := b.String(); h.injectSRI(in) != old(in) {
			t.Errorf("injectSRI mismatch on %q:\ngot:  %q\nwant: %q", in, h.injectSRI(in), old(in))
		}
	}
	out := h.injectSRI(string(page))
	for _, tag := range regexp.MustCompile(`<(?:script|link)\s[^>]*(?:src|href)="/(?:js|css|vendor)[^>]*>`).FindAllString(out, -1) {
		if !strings.Contains(tag, "integrity=") {
			t.Errorf("no integrity: %s", tag)
		}
	}
}

// TestETagRevalidation: a cached asset answers If-None-Match with a bodyless
// 304, and a changed/unknown tag gets the full body.
func TestETagRevalidation(t *testing.T) {
	h := newTestHandler(t, "#fab283")
	get := func(inm string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/app.js", nil)
		if inm != "" {
			r.Header.Set("If-None-Match", inm)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	first := get("")
	etag := first.Header().Get("ETag")
	if first.Code != 200 || !strings.HasPrefix(etag, `W/"sha256-`) {
		t.Fatalf("first GET: code %d etag %q", first.Code, etag)
	}
	if w := get(etag); w.Code != 304 || w.Body.Len() != 0 {
		t.Fatalf("revalidate: code %d body %d, want 304 empty", w.Code, w.Body.Len())
	}
	if w := get(`W/"sha256-stale"`); w.Code != 200 {
		t.Fatalf("stale tag: code %d, want 200", w.Code)
	}
}
