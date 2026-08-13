// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shells/internal/auth"
	"shells/internal/config"
	"shells/internal/crypto"
	"shells/internal/session"
)

func apiTestConfig(t *testing.T) *config.Config {
	t.Helper()
	shell, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash not found: %v", err)
	}
	return &config.Config{
		MaxSessions:     4,
		DefaultShell:    shell,
		Cwd:             "/",
		OutputBufferMax: 65536,
		ShellEnvKeys:    []string{},
		TrustProxy:      true,
	}
}

func newTestHandler(t *testing.T, cfg *config.Config) (*Handler, *session.Manager) {
	t.Helper()
	mgr, err := session.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{cfg: cfg, manager: mgr, rateLimits: map[string][]time.Time{}}, mgr
}

func TestHandleSessionsBadCwdFailsLoud(t *testing.T) {
	h, mgr := newTestHandler(t, apiTestConfig(t))
	missing := filepath.Join(t.TempDir(), "nonexistent")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", nil)
	h.handleSessions(rec, req, map[string]any{"cols": 80, "rows": 24, "command": "bash", "cwd": missing}, "POST")

	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "cwd_unusable" {
		t.Fatalf("code=%q", resp.Code)
	}
	if !strings.Contains(resp.Error, missing) {
		t.Fatalf("error does not mention path: %q", resp.Error)
	}
	if mgr.Count() != 0 {
		t.Fatalf("a session was silently created despite unusable cwd: count=%d", mgr.Count())
	}
}

func TestHandleSessionsValidCwd(t *testing.T) {
	h, mgr := newTestHandler(t, apiTestConfig(t))
	dir := t.TempDir()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", nil)
	h.handleSessions(rec, req, map[string]any{"cols": 80, "rows": 24, "cwd": dir}, "POST")

	if rec.Code != 201 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Cwd string `json:"cwd"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Cwd != dir {
		t.Fatalf("cwd=%q want %q", resp.Cwd, dir)
	}
	mgr.DestroyAll()
}

func TestHandleSessionsCommandNotFound(t *testing.T) {
	h, mgr := newTestHandler(t, apiTestConfig(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", nil)
	h.handleSessions(rec, req, map[string]any{"cols": 80, "rows": 24, "command": "definitely-not-a-binary-xyz", "cwd": t.TempDir()}, "POST")

	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "command_not_found" {
		t.Fatalf("code=%q", resp.Code)
	}
	if mgr.Count() != 0 {
		t.Fatalf("a session was silently created despite missing command: count=%d", mgr.Count())
	}
}

func TestSessionsCommandNotFoundOverWire(t *testing.T) {
	// Exercise the full encrypted HTTP path a browser would use: session token
	// + AES-GCM payload → ServeHTTP → decrypted response with the error code.
	cfg := apiTestConfig(t)
	cfg.AppToken = "test-app-token"
	authStore := auth.NewStore(cfg.AppToken)
	mgr, err := session.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: cfg, manager: mgr, auth: authStore, rateLimits: map[string][]time.Time{}}

	token := "test-token-123"
	apiKey := []byte("0123456789abcdef0123456789abcdef")
	if err := authStore.Register(token, nil, apiKey); err != nil {
		t.Fatal(err)
	}

	plaintext, _ := json.Marshal(map[string]any{"cols": 80, "rows": 24, "command": "definitely-not-a-binary-xyz", "cwd": t.TempDir()})
	enc, err := crypto.EncryptApiPayload(apiKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(enc)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(body))
	req.Header.Set("X-Shells-Encrypted", "1")
	req.Header.Set("X-Shells-Token", token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var encResp struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &encResp); err != nil {
		t.Fatal(err)
	}
	dec, err := crypto.DecryptApiPayload(apiKey, encResp.Nonce, encResp.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(dec, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "command_not_found" {
		t.Fatalf("code=%q error=%q", resp.Code, resp.Error)
	}
	if mgr.Count() != 0 {
		t.Fatalf("a session was created despite missing command: count=%d", mgr.Count())
	}
}

func TestHandleRecentPathsPrunesStale(t *testing.T) {
	h, _ := newTestHandler(t, apiTestConfig(t))
	dir := t.TempDir()
	exists := filepath.Join(dir, "exists")
	if err := os.MkdirAll(exists, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "recent-paths.json")
	stale := []string{filepath.Join(dir, "gone"), "/definitely/missing/x", exists}
	raw, _ := json.Marshal(stale)
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.handleRecent(rec, map[string]any{}, file, "GET", statIsDir)

	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out []string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != exists {
		t.Fatalf("out=%v want [%s]", out, exists)
	}
	// The pruned list must be persisted so stale entries self-heal.
	persisted := readJSONStrings(t, file)
	if len(persisted) != 1 || persisted[0] != exists {
		t.Fatalf("persisted=%v want [%s]", persisted, exists)
	}
}

func TestHandleRecentCommandsDropsUnknown(t *testing.T) {
	h, _ := newTestHandler(t, apiTestConfig(t))
	file := filepath.Join(t.TempDir(), "recent-commands.json")
	rec := httptest.NewRecorder()
	h.handleRecent(rec, map[string]any{"commands": []any{"ls", "definitely-not-a-binary-xyz", "cd"}}, file, "POST", commandExists)

	if rec.Code != 200 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	persisted := readJSONStrings(t, file)
	if len(persisted) != 1 || persisted[0] != "ls" {
		t.Fatalf("persisted=%v want [ls]", persisted)
	}
}

func readJSONStrings(t *testing.T, file string) []string {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", file, err)
	}
	return out
}
