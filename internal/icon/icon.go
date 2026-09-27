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
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
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

	// PNG scanlines: a filter byte (0 = none) then non-premultiplied RGBA.
	stride := 1 + 4*size
	pix := make([]byte, stride*size)
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
				o := py*stride + 1 + 4*px
				pix[o], pix[o+1], pix[o+2], pix[o+3] = r, g, b, 255
			} else if a > 0 {
				o := py*stride + 1 + 4*px
				pix[o], pix[o+1], pix[o+2], pix[o+3] = ar, ag, ab, uint8(a*255+0.5)
			}
		}
	}

	return encodePNG(size, pix)
}

// encodePNG writes 8-bit RGBA scanlines (filter byte included) as a PNG —
// hand-rolled because image/png costs ~115 KB of binary for this one call.
func encodePNG(size int, scanlines []byte) ([]byte, error) {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(scanlines); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	ihdr := binary.BigEndian.AppendUint32(nil, uint32(size))
	ihdr = binary.BigEndian.AppendUint32(ihdr, uint32(size))
	ihdr = append(ihdr, 8, 6, 0, 0, 0) // 8-bit, RGBA, deflate, no filter, no interlace
	out := []byte("\x89PNG\r\n\x1a\n")
	for _, c := range []struct {
		typ  string
		data []byte
	}{{"IHDR", ihdr}, {"IDAT", z.Bytes()}, {"IEND", nil}} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(c.data)))
		start := len(out)
		out = append(append(out, c.typ...), c.data...)
		out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out[start:]))
	}
	return out, nil
}
