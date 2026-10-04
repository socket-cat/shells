// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shells/internal/config"
	"shells/internal/session"
)

func TestHandlePasteImageLocal(t *testing.T) {
	cfg := &config.Config{
		MaxSessions:     10,
		DefaultShell:    "/bin/sh",
		OutputBufferMax: 1000,
	}
	mgr, err := session.New(cfg)
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	h := New(cfg, mgr, nil, nil, nil)

	// Valid 1x1 PNG base64
	pngB64 := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPj/HwADBwEB4q+k8QAAAABJRU5ErkJggg=="

	sess, err := mgr.Create(80, 24, "/bin/sh", "/tmp", nil)
	if err != nil {
		t.Fatalf("mgr.Create: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/paste-image", nil)
	body := map[string]any{
		"image":     "data:image/png;base64," + pngB64,
		"sessionId": sess.ID,
	}

	h.handlePasteImage(w, r, body)

	if w.Code != 200 {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	respStr := w.Body.String()
	if !strings.Contains(respStr, `"/tmp/s-`) {
		t.Fatalf("expected /tmp/s- in response, got %s", respStr)
	}

	// Extract path from JSON
	var path string
	for _, part := range strings.Split(respStr, `"`) {
		if strings.HasPrefix(part, "/tmp/s-") {
			path = part
			break
		}
	}
	if path == "" {
		t.Fatalf("could not extract path from response %s", respStr)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file does not exist on disk: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("expected file mode 0600, got %o", mode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("dir stat failed: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0700 {
		t.Fatalf("expected dir mode 0700, got %o", mode)
	}

	// Verify exact file content matches original raw PNG bytes
	savedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}
	rawExpected, _ := base64.StdEncoding.DecodeString(pngB64)
	if string(savedBytes) != string(rawExpected) {
		t.Fatalf("saved file bytes do not match expected PNG payload")
	}

	// Verify session destruction cleans up the file
	mgr.Destroy(sess.ID)
	// Give onDestroy a moment to run
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		_ = os.Remove(path)
		t.Fatalf("expected file to be unlinked after session destroy, but it still exists")
	}
}

func TestHandlePasteImageRejectsInvalid(t *testing.T) {
	cfg := &config.Config{OutputBufferMax: 1000}
	h := New(cfg, nil, nil, nil, nil)

	// URL fetch of a non-image is rejected (uploads may be any type, URLs may not)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello plain text"))
	}))
	defer srv.Close()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/paste-image", nil)
	h.handlePasteImage(w, r, map[string]any{"url": srv.URL})
	if !strings.Contains(w.Body.String(), "unsupported image format") {
		t.Fatalf("expected unsupported image format error, got %s", w.Body.String())
	}

	// Empty body
	w2 := httptest.NewRecorder()
	h.handlePasteImage(w2, r, map[string]any{})
	if !strings.Contains(w2.Body.String(), "empty image") {
		t.Fatalf("expected empty image error, got %s", w2.Body.String())
	}

	// SSRF attempt to cloud metadata
	w3 := httptest.NewRecorder()
	h.handlePasteImage(w3, r, map[string]any{"url": "http://169.254.169.254/latest/meta-data"})
	if !strings.Contains(w3.Body.String(), "prohibited image url host") {
		t.Fatalf("expected prohibited image url host error, got %s", w3.Body.String())
	}
}

func TestEvictOldest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "paste-evict-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create 5 files with staggered timestamps
	for i := 0; i < 5; i++ {
		p := filepath.Join(tmpDir, string(rune('a'+i))+".png")
		if err := os.WriteFile(p, []byte("testdata"), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Subtest 1: under budget -> no eviction
	evictOldest(tmpDir, 100)
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 files, got %d", len(entries))
	}

	// Subtest 2: incoming bytes exceed maxPasteDirBytes (50MB) -> evicts oldest files first
	evictOldest(tmpDir, maxPasteDirBytes)
	entriesAfter, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	// With incomingBytes == maxPasteDirBytes, totalSize must be 0 to fit, so all are evicted
	if len(entriesAfter) != 0 {
		t.Fatalf("expected 0 files after eviction exceeding budget, got %d", len(entriesAfter))
	}
}

func TestHandlePasteAnyFile(t *testing.T) {
	h := New(&config.Config{OutputBufferMax: 1000}, nil, nil, nil, nil)
	for name, want := range map[string]string{
		"report.XLSX":    ".xlsx",
		"../../x.sh;rm":  "",
		"a.toolongext12": "",
		"":               "",
	} {
		w := httptest.NewRecorder()
		h.handlePasteImage(w, httptest.NewRequest("POST", "/api/paste-image", nil), map[string]any{
			"image": base64.StdEncoding.EncodeToString([]byte("PK\x03\x04 not an image")),
			"name":  name,
		})
		var resp struct{ Path, Error string }
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Path == "" || filepath.Dir(resp.Path) != pasteDir() || filepath.Ext(resp.Path) != want {
			t.Fatalf("name %q: want ext %q in %s, got %s", name, want, pasteDir(), w.Body.String())
		}
		_ = os.Remove(resp.Path)
	}
}

func TestSecurePasteDir(t *testing.T) {
	base := t.TempDir()
	good := filepath.Join(base, "good")
	_ = os.Mkdir(good, 0777)
	if err := securePasteDir(good); err != nil {
		t.Fatalf("own dir should be accepted (and tightened): %v", err)
	}
	link := filepath.Join(base, "link")
	_ = os.Symlink(good, link)
	if securePasteDir(link) == nil {
		t.Fatal("symlinked dir must be refused")
	}
	file := filepath.Join(base, "file")
	_ = os.WriteFile(file, nil, 0600)
	if securePasteDir(file) == nil {
		t.Fatal("non-dir must be refused")
	}
}
