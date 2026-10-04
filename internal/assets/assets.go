// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package assets maps public/ to the shipped file set. The versioned
// <script>/<link rel=stylesheet> tags in index.html are concatenated, in order,
// into bundle.js / bundle.css (53 → 13 requests on a cold load; the build omits
// HTTP/2), sw.js precaches the bundles instead of their sources, and the
// sources themselves are not shipped. fonts/ CSS stays separate: its relative
// url()s must resolve from its own directory.
package assets

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

var (
	jsTag  = regexp.MustCompile(`<script src="/([^"?]+\.js)\?v=\{\{VERSION\}\}"></script>\n`)
	cssTag = regexp.MustCompile(`<link rel="stylesheet" href="/((?:css|vendor)/[^"?]+\.css)\?v=\{\{VERSION\}\}">\n`)
)

// Build returns every shipped file under dir, keyed by slash path relative to it.
func Build(dir string) (map[string][]byte, error) {
	fsys := os.DirFS(dir)
	out := map[string][]byte{}
	if err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		out[p], err = fs.ReadFile(fsys, p)
		return err
	}); err != nil {
		return nil, err
	}
	html := string(out["index.html"])
	for _, b := range []struct {
		re        *regexp.Regexp
		name, sep string
	}{{jsTag, "bundle.js", "\n;\n"}, {cssTag, "bundle.css", "\n"}} {
		var err error
		if html, err = bundle(out, html, b.re, b.name, b.sep); err != nil {
			return nil, err
		}
	}
	out["index.html"] = []byte(html)

	var sw []string // precache the bundles instead of their sources
	for _, line := range strings.SplitAfter(string(out["sw.js"]), "\n") {
		entry := strings.TrimSpace(line)
		if _, shipped := out[strings.Trim(entry, "/',")]; shipped || !strings.HasPrefix(entry, "'/") {
			sw = append(sw, line)
		}
		if strings.HasPrefix(line, "const STATIC_ASSETS = [") {
			sw = append(sw, "  '/bundle.js',\n  '/bundle.css',\n")
		}
	}
	out["sw.js"] = []byte(strings.Join(sw, ""))
	return out, nil
}

// bundle concatenates (with sep) the files tagged by re in html into name,
// removes them from out, and puts one tag for name where the first one stood.
func bundle(out map[string][]byte, html string, re *regexp.Regexp, name, sep string) (string, error) {
	var parts []string
	var missing []string
	html = re.ReplaceAllStringFunc(html, func(m string) string {
		f := re.FindStringSubmatch(m)[1]
		b, ok := out[f]
		if !ok {
			missing = append(missing, f)
		}
		parts = append(parts, string(b))
		delete(out, f)
		if len(parts) > 1 {
			return ""
		}
		return strings.Replace(m, f, name, 1)
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("index.html references missing assets: %v", missing)
	}
	out[name] = []byte(strings.Join(parts, sep))
	return html, nil
}
