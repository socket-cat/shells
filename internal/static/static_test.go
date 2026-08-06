// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat) <ragull@socket.cat>

package static

import (
	"bytes"
	"image"
	"image/png"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/fstest"

	"shells/internal/branding"
)

func testFS() *fstest.MapFS {
	return &fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte(`<!DOCTYPE html><html><head><title>{{APP_NAME}}</title></head><body></body></html>`)},
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
