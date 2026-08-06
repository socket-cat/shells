// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat) <ragull@socket.cat>

// Package icon renders the application's hexagon mark to PNG using only the Go
// standard library — no external SVG/vector rasterizer dependency.
//
// The geometry mirrors public/icon.svg exactly (a 512×512 design canvas, a
// regular hexagon outline with a 44-unit rounded stroke) so raster and vector
// icons are visually identical. Edges are anti-aliased analytically via a
// distance-to-outline field, which avoids the need for supersampling and keeps
// rendering fast enough to regenerate on demand when the branding accent
// changes.
package icon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"strings"
)

// Design-canvas geometry. Keep in sync with public/icon.svg.
const (
	canvas     = 512.0
	stroke     = 44.0
	strokeHalf = stroke / 2.0
)

// hexagon lists the outline vertices in design-canvas coordinates, matching the
// <path d="M256 52 L432.67 154 …"> in icon.svg.
var hexagon = [...][2]float64{
	{256, 52},
	{432.67, 154},
	{432.67, 358},
	{256, 460},
	{79.33, 358},
	{79.33, 154},
}

// distToSegment returns the Euclidean distance from point p to segment ab.
func distToSegment(px, py, ax, ay, bx, by float64) float64 {
	abx, aby := bx-ax, by-ay
	apx, apy := px-ax, py-ay
	len2 := abx*abx + aby*aby
	t := 0.0
	if len2 > 0 {
		t = (apx*abx + apy*aby) / len2
	}
	if t < 0 {
		t = 0
	} else if t > 1 {
		t = 1
	}
	cx := ax + t*abx
	cy := ay + t*aby
	dx := px - cx
	dy := py - cy
	return math.Sqrt(dx*dx + dy*dy)
}

// distOutline returns the minimum distance from p to the hexagon outline.
// Because each edge is treated as a finite segment, the field produces rounded
// line joins at the vertices (matching stroke-linejoin="round").
func distOutline(x, y float64) float64 {
	best := math.MaxFloat64
	for i := 0; i < len(hexagon); i++ {
		a := hexagon[i]
		b := hexagon[(i+1)%len(hexagon)]
		d := distToSegment(x, y, a[0], a[1], b[0], b[1])
		if d < best {
			best = d
		}
	}
	return best
}

// ParseColor parses a #RRGGBB string into 8-bit components.
func ParseColor(s string) (r, g, b uint8, err error) {
	s = strings.TrimSpace(s)
	h := strings.TrimPrefix(s, "#")
	if len(h) != 6 {
		return 0, 0, 0, fmt.Errorf("icon: invalid color %q (want #RRGGBB)", s)
	}
	buf, err := hex.DecodeString(h)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("icon: invalid color %q: %w", s, err)
	}
	return buf[0], buf[1], buf[2], nil
}

// RenderPNG rasterizes the hexagon mark into an size×size PNG.
//
// accent is the #RRGGBB stroke color. bg is the optional #RRGGBB background
// fill; when empty the background is fully transparent. The design canvas is
// scaled to fit the target size, preserving the icon's padding so raster and
// vector outputs match.
func RenderPNG(size int, accent, bg string) ([]byte, error) {
	if size < 16 || size > 1024 {
		return nil, fmt.Errorf("icon: size %d out of range (16..1024)", size)
	}
	ar, ag, ab, err := ParseColor(accent)
	if err != nil {
		return nil, err
	}
	var br, bgc, bb uint8
	hasBG := false
	if bg != "" {
		br, bgc, bb, err = ParseColor(bg)
		if err != nil {
			return nil, err
		}
		hasBG = true
	}

	rect := image.Rect(0, 0, size, size)
	img := image.NewRGBA(rect)
	scale := canvas / float64(size)
	// Anti-aliasing band of ~1 device pixel, expressed in canvas units so the
	// smoothing stays ~1px regardless of output size.
	band := scale

	for py := 0; py < size; py++ {
		cy := (float64(py) + 0.5) * scale
		for px := 0; px < size; px++ {
			cx := (float64(px) + 0.5) * scale
			d := distOutline(cx, cy)
			// Coverage: 1 well inside the stroke, 0 well outside.
			a := (strokeHalf + band/2 - d) / band
			if a > 1 {
				a = 1
			}
			if hasBG {
				if a < 0 {
					a = 0
				}
				// Blend opaque background → opaque accent by coverage.
				r := uint8(float64(br)*(1-a) + float64(ar)*a + 0.5)
				g := uint8(float64(bgc)*(1-a) + float64(ag)*a + 0.5)
				b := uint8(float64(bb)*(1-a) + float64(ab)*a + 0.5)
				img.SetRGBA(px, py, color.RGBA{R: r, G: g, B: b, A: 255})
			} else if a > 0 {
				img.SetRGBA(px, py, color.RGBA{R: ar, G: ag, B: ab, A: uint8(a*255 + 0.5)})
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
