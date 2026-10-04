// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package assets

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestBuildBundles(t *testing.T) {
	files, err := Build("../../public")
	if err != nil {
		t.Fatal(err)
	}
	html, sw := string(files["index.html"]), string(files["sw.js"])
	for _, m := range append(jsTag.FindAllStringSubmatch(html, -1), cssTag.FindAllStringSubmatch(html, -1)...) {
		if m[1] != "bundle.js" && m[1] != "bundle.css" {
			t.Errorf("index.html still references unbundled %s", m[1])
		}
	}
	if strings.Count(html, "/bundle.js?v=") != 1 || strings.Count(html, "/bundle.css?v=") != 1 {
		t.Error("index.html must reference each bundle exactly once")
	}
	for _, src := range []string{"js/app.js", "vendor/xterm.js", "css/base.css"} {
		if _, ok := files[src]; ok {
			t.Errorf("%s shipped alongside its bundle", src)
		}
		if strings.Contains(sw, "'/"+src+"'") {
			t.Errorf("sw.js still precaches %s", src)
		}
	}
	// Order is load order: xterm first, app.js (the entrypoint) last.
	xterm, _ := os.ReadFile("../../public/vendor/xterm.js")
	app, _ := os.ReadFile("../../public/js/app.js")
	if !bytes.HasPrefix(files["bundle.js"], xterm) || !bytes.HasSuffix(files["bundle.js"], app) {
		t.Error("bundle.js order differs from index.html")
	}
}
