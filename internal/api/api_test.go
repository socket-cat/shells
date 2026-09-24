// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"shells/internal/auth"
	"shells/internal/config"
	"shells/internal/crypto"
	"shells/internal/pty"
	"shells/internal/session"
	"shells/internal/ssh"
	"shells/internal/util"
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
	return &Handler{cfg: cfg, manager: mgr, rateLimiter: util.NewRateLimiter()}, mgr
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
	h := &Handler{cfg: cfg, manager: mgr, auth: authStore, rateLimiter: util.NewRateLimiter()}

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

// sshTestHandler wires a fake SSHValidate + SpawnSSH so the SSH branch of
// session.Create is exercised hermetically (no real sshd needed). The fake
// validation returns the given result.
func sshTestHandler(t *testing.T, cfg *config.Config, res session.ValidateResult) (*Handler, *session.Manager) {
	t.Helper()
	h, mgr := newTestHandler(t, cfg)
	mgr.SSHValidate = func(backend *session.Backend, command, cwd string) (session.ValidateResult, error) {
		return res, nil
	}
	mgr.SpawnSSH = func(backend *session.Backend, cols, rows int, command, cwd string) (*pty.Term, string, string, error) {
		return nil, "", "", errors.New("fake spawn reached")
	}
	return h, mgr
}

func sshBackendBody(host, user string) map[string]any {
	return map[string]any{
		"cols": 80,
		"rows": 24,
		"backend": map[string]any{
			"type":         "ssh",
			"connectionId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"host":         host,
			"user":         user,
			"port":         22,
		},
	}
}

func TestHandleSessionsSSHCwdBad(t *testing.T) {
	h, mgr := sshTestHandler(t, apiTestConfig(t), session.ValidateCwdBad)
	body := sshBackendBody("h", "u")
	body["cwd"] = "/nonexistent-xyz"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", nil)
	h.handleSessions(rec, req, body, "POST")

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
	if !strings.Contains(resp.Error, "/nonexistent-xyz") {
		t.Fatalf("error does not mention path: %q", resp.Error)
	}
	if mgr.Count() != 0 {
		t.Fatalf("a session was created despite unusable remote cwd: count=%d", mgr.Count())
	}
}

func TestHandleSessionsSSHCmdBad(t *testing.T) {
	h, mgr := sshTestHandler(t, apiTestConfig(t), session.ValidateCmdBad)
	body := sshBackendBody("h", "u")
	body["command"] = "definitely-not-a-binary-xyz"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", nil)
	h.handleSessions(rec, req, body, "POST")

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
		t.Fatalf("a session was created despite missing remote command: count=%d", mgr.Count())
	}
}

func TestHandleSessionsSSHConnErrorProceeds(t *testing.T) {
	h, mgr := sshTestHandler(t, apiTestConfig(t), session.ValidateConnError)
	body := sshBackendBody("h", "u")
	body["cwd"] = "/nonexistent-xyz"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", nil)
	h.handleSessions(rec, req, body, "POST")

	// connError must NOT block spawn: Create reaches SpawnSSH and fails there
	// (fake "fake spawn reached"), not with a validation error code.
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
	if resp.Code != "create_failed" {
		t.Fatalf("code=%q want create_failed (spawn reached)", resp.Code)
	}
	if mgr.Count() != 0 {
		t.Fatalf("count=%d", mgr.Count())
	}
}

// TestSessionsSSHBadCwdOverWire runs the FULL stack a browser would use
// against a real sshd: encrypted HTTP → handleSessions → session.Create →
// ssh.ValidateRemote round-trip → typed code. Wires mgr.SSHValidate like
// main.go (sshMgr.Validate()). Gated on SHELLS_E2E=1; needs a key present in
// the keydir and authorized on the target (see ssh.TestValidateRemoteE2E).
func TestSessionsSSHBadCwdOverWire(t *testing.T) {
	if os.Getenv("SHELLS_E2E") != "1" {
		t.Skip("set SHELLS_E2E=1 to run live SSH e2e")
	}
	keyDir := os.Getenv("SHELLS_E2E_KEYDIR")
	if keyDir == "" {
		keyDir = "/tmp/shells-e2e-keydir"
	}
	if _, err := os.Stat(filepath.Join(keyDir, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")); err != nil {
		t.Skip("SSH key not present; run ssh.TestValidateRemoteE2E first")
	}
	host := os.Getenv("SHELLS_E2E_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	user := os.Getenv("SHELLS_E2E_USER")
	if user == "" {
		user = "x"
	}

	cfg := apiTestConfig(t)
	cfg.AppToken = "test-app-token"
	cfg.SSHAvailable = true
	cfg.SSHKeysDir = keyDir
	cfg.SSHConnectionsFile = filepath.Join(keyDir, "ssh-connections.json")
	authStore := auth.NewStore(cfg.AppToken)
	mgr, err := session.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sshMgr := ssh.NewManager(cfg)
	mgr.SpawnSSH = ssh.Spawn(cfg)
	mgr.SSHValidate = sshMgr.Validate()
	h := &Handler{cfg: cfg, manager: mgr, auth: authStore, rateLimiter: util.NewRateLimiter()}

	token := "test-token-123"
	apiKey := []byte("0123456789abcdef0123456789abcdef")
	if err := authStore.Register(token, nil, apiKey); err != nil {
		t.Fatal(err)
	}

	// Bogus remote folder → cwd_unusable (covers the recents-contamination bug).
	body := sshBackendBody(host, user)
	body["cwd"] = "/nonexistent-shells-e2e-xyz"
	plaintext, _ := json.Marshal(body)
	enc, err := crypto.EncryptApiPayload(apiKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	encBody, _ := json.Marshal(enc)
	req := httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(encBody))
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
		t.Fatalf("bad-cwd decrypted body: %s", dec)
	}
	if resp.Code != "cwd_unusable" {
		t.Fatalf("code=%q error=%q", resp.Code, resp.Error)
	}
	if mgr.Count() != 0 {
		t.Fatalf("a session was created despite bad remote cwd: count=%d", mgr.Count())
	}

	// Valid remote cwd + bare command → 201 (no false negative).
	okBody := sshBackendBody(host, user)
	okBody["cwd"] = "/tmp"
	okBody["command"] = "echo shells-e2e"
	plaintext, _ = json.Marshal(okBody)
	enc, err = crypto.EncryptApiPayload(apiKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	encBody, _ = json.Marshal(enc)
	req = httptest.NewRequest(http.MethodPost, "/api/sessions", bytes.NewReader(encBody))
	req.Header.Set("X-Shells-Encrypted", "1")
	req.Header.Set("X-Shells-Token", token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("valid cwd/cmd: code=%d body=%s", rec.Code, rec.Body.String())
	}
	mgr.DestroyAll()
}
