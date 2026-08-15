// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package static serves the embedded browser frontend with SRI (Subresource
// Integrity) hash injection, {{VERSION}}/{{HOSTNAME}} template substitution,
// and gzip compression.
//
// At construction time every cacheable asset is read from the embed FS,
// templated, SHA-256 hashed, and cached in memory. The index.html receives
// integrity="sha256-…" attributes on all <script> and <link> tags so the
// browser can detect tampering.
package static

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"shells/internal/branding"
	"shells/internal/fsutil"
	"shells/internal/icon"
	"shells/internal/util"
)

var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "application/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".png":         "image/png",
	".svg":         "image/svg+xml",
	".woff2":       "font/woff2",
	".webmanifest": "application/manifest+json",
}

// Handler serves cached static assets with SRI and gzip.
type Handler struct {
	publicFS fs.FS
	version  string
	hostname string
	accent   string
	appName  string
	brand    *branding.Store

	// Pre-processed asset bodies keyed by request path (e.g. "/js/crypto.js").
	assets map[string][]byte
	// SRI hashes keyed by request path: "sha256-…".
	hashes map[string]string

	// iconMu guards the generated-icon cache.
	iconMu sync.Mutex
	// iconGen is the accent the cached icons were rendered for.
	iconGen string
	// iconPngs holds rendered icon bodies keyed by request path.
	iconPngs map[string][]byte
}

// New reads all assets from publicFS, applies template substitution,
// computes SRI hashes, injects them into index.html, and optionally writes
// an extension manifest to keyDir.
func New(publicFS fs.FS, version, keyDir, accent, appName string, brand *branding.Store) (*Handler, error) {
	hostname, _ := os.Hostname()
	if !util.ValidHostname(hostname) {
		hostname = ""
	}

	h := &Handler{
		publicFS: publicFS,
		version:  version,
		hostname: hostname,
		accent:   accent,
		appName:  appName,
		brand:    brand,
		assets:   make(map[string][]byte),
		hashes:   make(map[string]string),
	}

	if err := h.processAssets(); err != nil {
		return nil, err
	}

	if keyDir != "" {
		h.writeManifest(keyDir)
	}

	return h, nil
}

func (h *Handler) processAssets() error {
	// Walk all files, template + hash everything except index.html (handled last).
	var paths []string
	_ = fs.WalkDir(h.publicFS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	sort.Strings(paths)

	for _, p := range paths {
		if p == "index.html" {
			continue
		}
		raw, err := fs.ReadFile(h.publicFS, p)
		if err != nil {
			continue
		}
		reqPath := "/" + filepath.ToSlash(p)
		body := h.template(raw, reqPath)
		h.storeAsset(reqPath, body)
	}

	// Process index.html: template → inject SRI → hash.
	htmlRaw, err := fs.ReadFile(h.publicFS, "index.html")
	if err != nil {
		return err
	}
	html := string(htmlRaw)
	html = strings.ReplaceAll(html, "{{VERSION}}", h.version)
	html = strings.ReplaceAll(html, "{{HOSTNAME}}", h.hostname)
	html = strings.ReplaceAll(html, "{{ACCENT}}", h.accent)
	html = strings.ReplaceAll(html, "{{APP_NAME}}", htmlEscape(h.appName))
	html = h.injectSRI(html)

	h.storeAsset("/index.html", []byte(html))
	h.storeAsset("/", []byte(html))
	return nil
}

// substitute replaces the {{TOKEN}} placeholders. Substitution order and
// escaping are load-bearing: keep VERSION→HOSTNAME→ACCENT→APP_NAME→
// APP_NAME_JSON and htmlEscape(appName) exactly as-is.
func substitute(raw []byte, version, hostname, accent, appName string) []byte {
	s := strings.ReplaceAll(string(raw), "{{VERSION}}", version)
	s = strings.ReplaceAll(s, "{{HOSTNAME}}", hostname)
	s = strings.ReplaceAll(s, "{{ACCENT}}", accent)
	s = strings.ReplaceAll(s, "{{APP_NAME}}", htmlEscape(appName))
	b, _ := json.Marshal(appName)
	s = strings.ReplaceAll(s, "{{APP_NAME_JSON}}", string(b))
	return []byte(s)
}

func (h *Handler) template(raw []byte, reqPath string) []byte {
	ext := filepath.Ext(reqPath)
	if ext == ".html" || ext == ".js" || ext == ".svg" || ext == ".webmanifest" {
		return substitute(raw, h.version, h.hostname, h.accent, h.appName)
	}
	return raw
}

// templateLive templates an asset with the CURRENT branding (not the startup
// snapshot), so the served manifest/icon/sw.js reflect server-side edits and
// the browser updates the installed PWA's name/icon.
func (h *Handler) templateLive(raw []byte) []byte {
	st := h.brand.Get()
	return substitute(raw, h.version, h.hostname, st.Accent, st.AppName)
}

// brandAssets are served dynamically (per-request) from the current branding.
var brandAssets = map[string]string{
	"/manifest.webmanifest": "manifest.webmanifest",
	"/icon.svg":             "icon.svg",
	"/sw.js":                "sw.js",
}

// generatedIcons are raster icons rendered on demand from the current branding
// accent. SVG cannot be used for iOS apple-touch-icon or legacy PWA installs,
// so these provide the fallback. Rendering is cached per accent and only
// re-runs when the branding accent changes.
var generatedIcons = map[string]struct {
	size int
	bg   string
}{
	"/apple-touch-icon.png": {size: 180, bg: "#0a0a0a"},
	"/icon-192.png":         {size: 192, bg: ""},
	"/icon-512.png":         {size: 512, bg: ""},
}

// generatedIcon returns the rendered icon body for reqPath, using the current
// branding accent. It returns nil when reqPath is not a generated icon path.
// The render is cached and invalidated whenever the accent changes.
func (h *Handler) generatedIcon(reqPath string) []byte {
	spec, ok := generatedIcons[reqPath]
	if !ok {
		return nil
	}
	st := h.brand.Get()
	accent := st.Accent
	if !branding.ValidAccent(accent) {
		accent = h.accent
	}

	h.iconMu.Lock()
	defer h.iconMu.Unlock()
	if h.iconGen != accent {
		h.iconPngs = make(map[string][]byte)
		h.iconGen = accent
	}
	if b, ok := h.iconPngs[reqPath]; ok {
		return b
	}
	b, err := icon.RenderPNG(spec.size, accent, spec.bg)
	if err != nil || len(b) == 0 {
		return nil
	}
	h.iconPngs[reqPath] = b
	return b
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func (h *Handler) storeAsset(reqPath string, body []byte) {
	sum := sha256.Sum256(body)
	hash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	h.assets[reqPath] = body
	h.hashes[reqPath] = hash
}

var (
	scriptSRI = regexp.MustCompile(`(<script\s[^>]*src=["']([^"']+)["'][^>]*?)(>)`)
	linkSRI   = regexp.MustCompile(`(<link\s[^>]*href=["']([^"']+)["'][^>]*?)(>)`)
)

func (h *Handler) injectSRI(html string) string {
	html = scriptSRI.ReplaceAllStringFunc(html, func(match string) string {
		sub := scriptSRI.FindStringSubmatch(match)
		return h.injectAttr(sub[1], sub[2], sub[3])
	})
	html = linkSRI.ReplaceAllStringFunc(html, func(match string) string {
		// Branding links (manifest/icon) are served dynamically; skip SRI so a
		// stale integrity attribute can't block the fresh content.
		low := strings.ToLower(match)
		if strings.Contains(low, `rel="manifest"`) || strings.Contains(low, `rel="icon"`) || strings.Contains(low, `rel="apple-touch-icon"`) {
			return match
		}
		sub := linkSRI.FindStringSubmatch(match)
		return h.injectAttr(sub[1], sub[2], sub[3])
	})
	return html
}

func (h *Handler) injectAttr(prefix, srcURL, suffix string) string {
	// Strip query string from the URL for hash lookup.
	cleanURL := srcURL
	if idx := strings.IndexByte(cleanURL, '?'); idx >= 0 {
		cleanURL = cleanURL[:idx]
	}
	hash, ok := h.hashes[cleanURL]
	if !ok {
		return prefix + suffix
	}
	return prefix + ` integrity="` + hash + `" crossorigin="anonymous"` + suffix
}

func (h *Handler) writeManifest(keyDir string) {
	manifest := map[string]any{
		"version":     h.version,
		"generatedAt": time.Now().UTC().Format(time.RFC3339),
		"hashes":      h.hashes,
	}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	manifestPath := filepath.Join(keyDir, "extension-manifest.json")
	_ = fsutil.AtomicWrite(manifestPath, data)
}

// ServeHTTP serves a static asset.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqPath := path.Clean(r.URL.Path)
	if reqPath == "/" {
		reqPath = "/index.html"
	}

	// Prevent path traversal (embed FS already sandboxes, but belt-and-suspenders).
	if strings.Contains(reqPath, "..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Raster icons are rendered on demand from the current branding accent.
	if body := h.generatedIcon(reqPath); body != nil {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	// Branding-dependent assets are generated per-request from the current
	// server-side branding so the installed PWA's name/icon track edits.
	if embedName, isBrand := brandAssets[reqPath]; isBrand {
		raw, err := fs.ReadFile(h.publicFS, embedName)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		body := h.templateLive(raw)
		ext := strings.ToLower(filepath.Ext(reqPath))
		ct := contentTypes[ext]
		if ct == "" {
			ct = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	// index.html is templated per-request with the CURRENT branding (title,
	// inline --accent, data-* attributes) and carries the live SRI attributes,
	// so branding edits are reflected without a server restart.
	if reqPath == "/index.html" {
		raw, err := fs.ReadFile(h.publicFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		body := h.templateLive(raw)
		body = []byte(h.injectSRI(string(body)))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}

	body, ok := h.assets[reqPath]
	if !ok {
		// Try reading from the embed FS directly (non-cacheable files).
		embedPath := strings.TrimPrefix(reqPath, "/")
		raw, err := fs.ReadFile(h.publicFS, embedPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		body = h.template(raw, reqPath)
	}

	ext := strings.ToLower(filepath.Ext(reqPath))
	contentType := contentTypes[ext]
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)

	// Cache control.
	switch {
	case reqPath == "/sw.js" || reqPath == "/pwa.js" || ext == ".webmanifest":
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	case h.assets[reqPath] != nil && ext != ".woff2":
		w.Header().Set("Cache-Control", "no-cache")
	}

	// gzip.
	if acceptsGzip(r) && len(body) > 512 {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		w.WriteHeader(http.StatusOK)
		gz := gzip.NewWriter(w)
		_, _ = gz.Write(body)
		_ = gz.Close()
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func acceptsGzip(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}
