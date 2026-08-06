// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat) <ragull@socket.cat>

package icon

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestParseColor(t *testing.T) {
	r, g, b, err := ParseColor("#fab283")
	if err != nil || r != 0xfa || g != 0xb2 || b != 0x83 {
		t.Fatalf("ParseColor(#fab283) = (%02x,%02x,%02x,%v), want (fa,b2,83,nil)", r, g, b, err)
	}
	// Without the leading # is also accepted (TrimPrefix is lenient).
	if _, _, _, err := ParseColor("fab283"); err != nil {
		t.Fatalf("ParseColor(fab283) want ok, got %v", err)
	}
	if _, _, _, err := ParseColor("#abc"); err == nil {
		t.Fatal("ParseColor(#abc) want error for short hex")
	}
	if _, _, _, err := ParseColor("##fab283"); err == nil {
		t.Fatal("ParseColor(##fab283) want error for extra #")
	}
	if _, _, _, err := ParseColor("#gggggg"); err == nil {
		t.Fatal("ParseColor(#gggggg) want error for non-hex")
	}
}

func mustDecode(t *testing.T, b []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("png.Decode: %v", err)
	}
	return img
}

// TestRenderPNGShape checks geometry: the stroke is the accent, the center
// (inside the hexagon) is background/transparent, and a corner is transparent.
func TestRenderPNGShape(t *testing.T) {
	const accent = "#fab283"
	body, err := RenderPNG(512, accent, "")
	if err != nil {
		t.Fatalf("RenderPNG: %v", err)
	}
	img := mustDecode(t, body)
	if b := img.Bounds().Dx(); b != 512 {
		t.Fatalf("width = %d, want 512", b)
	}

	// Top vertex (256,52) lies on the outline → accent, opaque.
	c := color.NRGBAModel.Convert(img.At(256, 52)).(color.NRGBA)
	if c.R != 0xfa || c.G != 0xb2 || c.B != 0x83 || c.A == 0 {
		t.Fatalf("outline pixel = %+v, want accent opaque", c)
	}

	// Center (256,256) is inside the hexagon ring → transparent.
	c = color.NRGBAModel.Convert(img.At(256, 256)).(color.NRGBA)
	if c.A != 0 {
		t.Fatalf("center pixel = %+v, want transparent", c)
	}

	// Far corner (5,5) is well outside → transparent.
	c = color.NRGBAModel.Convert(img.At(5, 5)).(color.NRGBA)
	if c.A != 0 {
		t.Fatalf("corner pixel = %+v, want transparent", c)
	}
}

func TestRenderPNGBBackground(t *testing.T) {
	body, err := RenderPNG(256, "#fab283", "#0a0a0a")
	if err != nil {
		t.Fatalf("RenderPNG: %v", err)
	}
	img := mustDecode(t, body)

	// With a background, the center is the opaque background color.
	c := color.NRGBAModel.Convert(img.At(128, 128)).(color.NRGBA)
	if c.A != 255 || c.R != 0x0a || c.G != 0x0a || c.B != 0x0a {
		t.Fatalf("center pixel = %+v, want opaque #0a0a0a", c)
	}
	// Corner is also the opaque background.
	c = color.NRGBAModel.Convert(img.At(2, 2)).(color.NRGBA)
	if c.A != 255 {
		t.Fatalf("corner pixel alpha = %d, want 255", c.A)
	}
	// Outline is the accent.
	c = color.NRGBAModel.Convert(img.At(128, 26)).(color.NRGBA)
	if c.R != 0xfa || c.G != 0xb2 || c.B != 0x83 || c.A != 255 {
		t.Fatalf("outline pixel = %+v, want accent opaque", c)
	}
}

func TestRenderPNGValidHeader(t *testing.T) {
	body, err := RenderPNG(180, "#ffffff", "")
	if err != nil {
		t.Fatalf("RenderPNG: %v", err)
	}
	if !bytes.HasPrefix(body, []byte{0x89, 'P', 'N', 'G'}) {
		t.Fatal("missing PNG signature")
	}
}

func TestRenderPNGErrors(t *testing.T) {
	if _, err := RenderPNG(8, "#fab283", ""); err == nil {
		t.Fatal("size 8 want error")
	}
	if _, err := RenderPNG(64, "nope", ""); err == nil {
		t.Fatal("bad accent want error")
	}
	if _, err := RenderPNG(64, "#fab283", "bad"); err == nil {
		t.Fatal("bad background want error")
	}
}
