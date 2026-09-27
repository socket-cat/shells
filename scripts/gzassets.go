// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

//go:build ignore

// gzassets mirrors public/ into publicgz/ (gitignored, embedded by main.go)
// with every compressible file gzipped to NAME.gz — the binary carries ~0.7 MB
// instead of ~1.7 MB. woff2/png are already compressed and copied as-is.
// Run via `go generate` (scripts/build.sh does it).
package main

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"log"
	"os"
	"path/filepath"
)

func main() {
	if err := os.RemoveAll("publicgz"); err != nil {
		log.Fatal(err)
	}
	err := filepath.WalkDir("public", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("public", p)
		dst := filepath.Join("publicgz", rel)
		if ext := filepath.Ext(p); ext != ".woff2" && ext != ".png" {
			var buf bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
			zw.Write(b)
			if err := zw.Close(); err != nil {
				return err
			}
			b, dst = buf.Bytes(), dst+".gz"
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		log.Fatal(err)
	}
}
