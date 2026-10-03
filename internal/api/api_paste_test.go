// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/base64"
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

	// Non-image text
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/paste-image", nil)
	body := map[string]any{
		"image": base64.StdEncoding.EncodeToString([]byte("hello plain text")),
	}
	h.handlePasteImage(w, r, body)
	if !strings.Contains(w.Body.String(), "unsupported image format") {
		t.Fatalf("expected unsupported image format error, got %s", w.Body.String())
	}

	// Empty body
	w2 := httptest.NewRecorder()
	h.handlePasteImage(w2, r, map[string]any{})
	if !strings.Contains(w2.Body.String(), "empty image") {
		t.Fatalf("expected empty image error, got %s", w2.Body.String())
	}
}

func TestEvictOldest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "paste-evict-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create 5 files
	for i := 0; i < 5; i++ {
		p := filepath.Join(tmpDir, string(rune('a'+i))+".png")
		if err := os.WriteFile(p, []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond) // distinct mod times
	}

	// Call evictOldest with incoming bytes that fit within maxPasteDirBytes
	evictOldest(tmpDir, 100)

	// All 5 files should still exist since 5 < maxPasteDirFiles (50)
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 files, got %d", len(entries))
	}
}
