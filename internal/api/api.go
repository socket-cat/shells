// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package api implements the HTTP REST API for the shells server: session
// CRUD, directory listing, recent paths/commands persistence, and SSH
// management stubs. All sensitive endpoints require an encrypted channel
// (X-Shells-Encrypted) and a valid session token whose derived API key is
// used to decrypt the request body and encrypt the response.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"shells/internal/auth"
	"shells/internal/binpath"
	"shells/internal/branding"
	"shells/internal/config"
	"shells/internal/crypto"
	"shells/internal/release"
	"shells/internal/session"
	"shells/internal/ssh"
	"shells/internal/util"
)

// Handler routes /api/* requests.
type Handler struct {
	cfg     *config.Config
	manager *session.Manager
	auth    *auth.Store
	sshMgr  *ssh.Manager
	brand   *branding.Store

	startTime time.Time

	rateMu        sync.Mutex
	rateLimits    map[string][]time.Time
	lastRateSweep time.Time

	// Self-update check state: single-flight + short cache.
	updateMu       sync.Mutex
	updateInFlight bool
	updateDone     chan struct{}
	updateCache    *updateCacheEntry
}

type updateCacheEntry struct {
	info *release.Info
	at   time.Time
	ttl  time.Duration
}

// exitCodeRestart is the code the parent process interprets as "a staged update
// is ready — swap and restart". Matches restartCode in internal/selfupdate.
const exitCodeRestart = 42

// New creates an API handler.
func New(cfg *config.Config, mgr *session.Manager, authStore *auth.Store, sshMgr *ssh.Manager, brand *branding.Store) *Handler {
	return &Handler{
		cfg:        cfg,
		manager:    mgr,
		auth:       authStore,
		sshMgr:     sshMgr,
		brand:      brand,
		startTime:  time.Now(),
		rateLimits: make(map[string][]time.Time),
	}
}

// ServeHTTP routes the request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/api/health":
		h.handleHealth(w, r)
	case path == "/api/errors" && r.Method == http.MethodPost:
		h.handleErrors(w, r)
	case strings.HasPrefix(path, "/api/"):
		h.handleEncrypted(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	util.SendJSON(w, 200, map[string]any{
		"status":      "healthy",
		"version":     "v" + h.cfg.Version,
		"maxSessions": h.cfg.MaxSessions,
	}, nil)
}

func (h *Handler) handleErrors(w http.ResponseWriter, r *http.Request) {
	if !h.rateAllow("errors-"+h.clientIP(r), 30, time.Minute) {
		w.WriteHeader(204)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<12))
	if err == nil {
		var v map[string]any
		if json.Unmarshal(raw, &v) == nil {
			b, _ := json.Marshal(v)
			log.Printf("[Client Error] %s", string(b))
		} else {
			snippet := string(raw)
			snippet = strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return ' '
				}
				return r
			}, snippet)
			if len(snippet) > 100 {
				snippet = snippet[:100]
			}
			log.Printf("[Client Error] Malformed: %s", snippet)
		}
	}
	w.WriteHeader(204)
}

// --- encrypted endpoints ---

func (h *Handler) handleEncrypted(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Shells-Encrypted") != "1" {
		util.SendJSON(w, 400, map[string]any{"error": "Encryption required"}, nil)
		return
	}

	token := getToken(r)
	apiKey := h.auth.APIKeyForToken(token)
	if len(apiKey) == 0 {
		util.SendJSON(w, 401, map[string]any{"error": "Unauthorized"}, nil)
		return
	}

	body, err := decryptBody(apiKey, r)
	if err != nil {
		util.SendJSON(w, 400, map[string]any{"error": "Invalid encrypted payload"}, nil)
		return
	}

	ew := &util.EncryptedWriter{ResponseWriter: w, APIKey: apiKey}
	h.route(ew, r, body)
}

func (h *Handler) route(w http.ResponseWriter, r *http.Request, body map[string]any) {
	path := r.URL.Path
	method, _ := body["_method"].(string)

	switch {
	case path == "/api/sessions":
		h.handleSessions(w, r, body, method)
	case strings.HasPrefix(path, "/api/sessions/") && method == "DELETE":
		h.handleSessionDelete(w, path)
	case path == "/api/ls":
		h.handleLs(w, body)
	case path == "/api/which":
		q, _ := body["q"].(string)
		util.SendJSON(w, 200, map[string]any{"matches": binpath.Search(q)}, nil)
	case path == "/api/recent-paths":
		h.handleRecent(w, body, h.cfg.RecentPathsFile, method, statIsDir)
	case path == "/api/recent-commands":
		h.handleRecent(w, body, h.cfg.RecentCommandsFile, method, commandExists)
	case path == "/api/branding":
		h.handleBranding(w, r, body, method)
	case path == "/api/ssh-connections":
		h.handleSSHConnections(w, r, body, method)
	case strings.HasPrefix(path, "/api/ssh-connections/"):
		h.handleSSHConnectionDelete(w, body, path)
	case path == "/api/ssh-probe":
		h.handleSSHProbe(w, body, r)
	case path == "/api/ssh-setup":
		h.handleSSHSetup(w, body, r)
	case path == "/api/ssh-ls":
		h.handleSSHLs(w, body, r)
	case path == "/api/ssh-which":
		h.handleSSHWhich(w, body, r)
	case path == "/api/update-check":
		h.handleUpdateCheck(w, r, body)
	case path == "/api/update":
		h.handleUpdate(w, r)
	default:
		util.SendJSON(w, 404, map[string]any{"error": "Not found"}, nil)
	}
}

func (h *Handler) releaseConfig() release.Config {
	return release.Config{
		Version:      h.cfg.Version,
		Repo:         h.cfg.UpdateRepo,
		APIBase:      h.cfg.UpdateAPIBase,
		SigURL:       h.cfg.UpdateSigURL,
		ChecksumsURL: h.cfg.UpdateChecksumsURL,
		DownloadBase: h.cfg.UpdateDownloadBase,
		Platform:     release.Platform(),
		UserAgent:    "shells/" + h.cfg.Version,
		UpdateCheck:  h.cfg.UpdateCheck,
		BinaryPath:   h.cfg.BinaryPath,
	}
}

// handleUpdateCheck reports whether a verified newer release exists. Auto
// results are cached (success 1h, failure 5min) and single-flighted; a manual
// check (body force=true) bypasses the cache and always checks live.
func (h *Handler) handleUpdateCheck(w http.ResponseWriter, r *http.Request, body map[string]any) {
	if !h.rateAllow("update-check-"+h.clientIP(r), 5, time.Minute) {
		util.SendJSON(w, 429, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	force, _ := body["force"].(bool)
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	info := h.updateCheckResult(ctx, force)
	if info == nil {
		info = &release.Info{Error: "update check failed"}
	}
	if info.VerificationFailed {
		log.Printf("[update] VERIFICATION FAILED — possible tampering: %s", info.Error)
	}
	util.SendJSON(w, 200, info, map[string]string{"Cache-Control": "no-store"})
}

func (h *Handler) updateCheckResult(ctx context.Context, force bool) *release.Info {
	h.updateMu.Lock()
	if !force && h.updateCache != nil && time.Since(h.updateCache.at) < h.updateCache.ttl {
		info := h.updateCache.info
		h.updateMu.Unlock()
		return info
	}
	if h.updateInFlight {
		done := h.updateDone
		h.updateMu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil
		}
		h.updateMu.Lock()
		if h.updateCache != nil {
			info := h.updateCache.info
			h.updateMu.Unlock()
			return info
		}
		h.updateMu.Unlock()
		return nil
	}
	h.updateInFlight = true
	h.updateDone = make(chan struct{})
	h.updateMu.Unlock()

	info := release.CheckLatest(ctx, h.releaseConfig())

	h.updateMu.Lock()
	h.updateInFlight = false
	close(h.updateDone)
	if info != nil {
		ttl := time.Hour
		if info.Error != "" {
			ttl = 5 * time.Minute
		}
		h.updateCache = &updateCacheEntry{info: info, at: time.Now(), ttl: ttl}
	}
	h.updateMu.Unlock()
	return info
}

// handleUpdate stages the verified binary and exits with exitCodeRestart so
// the parent process swaps it in and restarts. The response is flushed before
// the exit fires.
func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.rateAllow("update-apply-"+h.clientIP(r), 2, time.Hour) {
		util.SendJSON(w, 429, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	version, err := release.Apply(ctx, h.releaseConfig())
	if err != nil {
		if errors.Is(err, release.ErrVerificationFailed) {
			log.Printf("[update] VERIFICATION FAILED — possible tampering: %v", err)
			util.SendJSON(w, 200, map[string]any{"applied": false, "verificationFailed": true, "error": "update verification failed"}, nil)
			return
		}
		util.SendJSON(w, 200, map[string]any{"applied": false, "error": "update failed"}, nil)
		return
	}
	util.SendJSON(w, 200, map[string]any{"applied": true, "version": version}, map[string]string{"Cache-Control": "no-store"})
	time.AfterFunc(1500*time.Millisecond, func() {
		log.Printf("[update] verified v%s staged — restarting to self-update", version)
		os.Exit(exitCodeRestart)
	})
}

func (h *Handler) handleSessions(w http.ResponseWriter, r *http.Request, body map[string]any, method string) {
	// GET (list)
	if method == "GET" || (method == "" && body["cols"] == nil) {
		list := make([]map[string]any, 0)
		for _, s := range h.manager.All() {
			list = append(list, map[string]any{
				"id":        s.ID,
				"pid":       s.Pid,
				"title":     s.GetTitle(),
				"cwd":       s.Cwd,
				"isRemote":  s.IsRemote,
				"createdAt": s.CreatedAt,
			})
		}
		util.SendJSON(w, 200, list, map[string]string{"Cache-Control": "no-store"})
		return
	}

	// POST (create)
	if body["cols"] != nil || method == "POST" {
		ip := h.clientIP(r)
		if !h.rateAllow("session-"+ip, 1000, time.Minute) {
			util.SendJSON(w, 429, map[string]any{"error": "Rate limit exceeded"}, nil)
			return
		}

		if h.manager.Count() >= h.cfg.MaxSessions {
			util.SendJSON(w, 403, map[string]any{"error": "Max sessions reached"}, nil)
			return
		}

		cols := util.IntFromAny(body["cols"])
		rows := util.IntFromAny(body["rows"])
		command, _ := body["command"].(string)
		cwd, _ := body["cwd"].(string)
		backend := parseBackend(body)

		s, err := h.manager.Create(cols, rows, command, cwd, backend)
		if err != nil {
			log.Printf("session create failed: %v", err)
			// 200 with error field: nginx error_page can't intercept a 200,
			// so the encrypted body reaches the browser cleanly. Never fall
			// back to a default session — that silently opens the wrong
			// directory and misleads the user.
			code := "create_failed"
			switch {
			case errors.Is(err, session.ErrCwdUnusable):
				code = "cwd_unusable"
			case errors.Is(err, session.ErrCommandNotFound):
				code = "command_not_found"
			}
			util.SendJSON(w, 200, map[string]any{"error": err.Error(), "code": code}, nil)
			return
		}
		util.SendJSON(w, 201, map[string]any{
			"id":       s.ID,
			"pid":      s.Pid,
			"cwd":      s.Cwd,
			"isRemote": s.IsRemote,
		}, nil)
		return
	}

	util.SendJSON(w, 400, map[string]any{"error": "Invalid request"}, nil)
}

func (h *Handler) handleSessionDelete(w http.ResponseWriter, path string) {
	id := strings.TrimPrefix(path, "/api/sessions/")
	if h.manager.Destroy(id) {
		w.WriteHeader(204)
	} else {
		util.SendJSON(w, 404, map[string]any{"error": "Session not found"}, nil)
	}
}

func (h *Handler) handleLs(w http.ResponseWriter, body map[string]any) {
	dir, _ := body["path"].(string)
	if dir == "" {
		dir = h.cfg.Cwd
	}

	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		util.SendJSON(w, 404, map[string]any{"error": "Path not found"}, nil)
		return
	}

	info, err := os.Stat(realDir)
	if err != nil || !info.IsDir() {
		util.SendJSON(w, 400, map[string]any{"error": "Not a directory"}, nil)
		return
	}

	entries, err := os.ReadDir(realDir)
	if err != nil {
		util.SendJSON(w, 500, map[string]any{"error": "Internal error"}, nil)
		return
	}

	var folders []string
	for _, entry := range entries {
		if entry.IsDir() {
			folders = append(folders, entry.Name())
			continue
		}
		// Check if symlink points to a directory.
		if entry.Type()&fs.ModeSymlink != 0 {
			full := filepath.Join(realDir, entry.Name())
			if st, err := os.Stat(full); err == nil && st.IsDir() {
				folders = append(folders, entry.Name())
			}
		}
	}

	sort.Strings(folders)
	util.SendJSON(w, 200, map[string]any{
		"path":    realDir,
		"parent":  filepath.Dir(realDir),
		"folders": folders,
	}, nil)
}

// handleBranding GET returns the current branding; POST updates it (persisted
// server-side so the served manifest/icon reflect it).
func (h *Handler) handleBranding(w http.ResponseWriter, r *http.Request, body map[string]any, method string) {
	if method == "POST" || method == "PUT" {
		if !h.rateAllow("branding-"+h.clientIP(r), 10, time.Minute) {
			util.SendJSON(w, 429, map[string]any{"error": "Rate limit exceeded"}, nil)
			return
		}
		name, _ := body["appName"].(string)
		accent, _ := body["accent"].(string)
		if err := h.brand.Set(name, accent); err != nil {
			util.SendJSON(w, 200, map[string]any{"error": "Failed to save branding"}, nil)
			return
		}
		util.SendJSON(w, 200, map[string]any{"success": true}, nil)
		return
	}
	st := h.brand.Get()
	util.SendJSON(w, 200, map[string]any{"appName": st.AppName, "accent": st.Accent}, nil)
}

// handleRecent reads or writes the recent paths/commands list. valid drops
// stale entries (paths that no longer exist, commands whose binary is gone) so
// the UI never suggests something that would fail.
func (h *Handler) handleRecent(w http.ResponseWriter, body map[string]any, file, method string, valid func(string) bool) {
	// GET
	if method == "GET" || (method == "" && body["paths"] == nil && body["commands"] == nil) {
		data, err := os.ReadFile(file)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				util.SendJSON(w, 200, []any{}, nil)
			} else {
				util.SendJSON(w, 500, map[string]any{"error": "Internal error"}, nil)
			}
			return
		}
		var parsed []string
		if json.Unmarshal(data, &parsed) != nil {
			util.SendJSON(w, 200, []any{}, nil)
			return
		}
		cleaned := filterRecent(parsed, valid)
		if len(cleaned) != len(parsed) {
			// Self-heal: persist the pruned list so stale entries are gone.
			if out, err := json.Marshal(cleaned); err == nil {
				_ = os.WriteFile(file, out, 0o600)
			}
		}
		util.SendJSON(w, 200, cleaned, nil)
		return
	}

	// POST
	items, ok := body["paths"].([]any)
	if !ok {
		items, ok = body["commands"].([]any)
	}
	if !ok {
		util.SendJSON(w, 400, map[string]any{"error": "Invalid data format"}, nil)
		return
	}

	strs := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok || s == "" {
			continue
		}
		strs = append(strs, s)
	}

	cleaned := filterRecent(strs, valid)
	data, _ := json.Marshal(cleaned)
	if err := os.WriteFile(file, data, 0o600); err != nil {
		util.SendJSON(w, 500, map[string]any{"error": "Internal error"}, nil)
		return
	}
	util.SendJSON(w, 200, map[string]any{"success": true}, nil)
}

// filterRecent keeps entries that pass valid, deduplicated and capped at 20.
func filterRecent(in []string, valid func(string) bool) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !valid(s) || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func statIsDir(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func commandExists(c string) bool {
	if c == "" || strings.ContainsAny(c, " \t") {
		return false
	}
	_, err := exec.LookPath(c)
	return err == nil
}

// --- helpers ---

func getToken(r *http.Request) string {
	if t := r.Header.Get("X-Shells-Token"); t != "" {
		return t
	}
	cookie := r.Header.Get("Cookie")
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "shells-token=") {
			return strings.TrimPrefix(part, "shells-token=")
		}
	}
	return ""
}

func decryptBody(apiKey []byte, r *http.Request) (map[string]any, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		return nil, err
	}
	var enc struct {
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(raw, &enc); err != nil {
		return nil, err
	}
	if enc.Nonce == "" || enc.Ciphertext == "" {
		return nil, errors.New("missing encryption fields")
	}
	plaintext, err := crypto.DecryptApiPayload(apiKey, enc.Nonce, enc.Ciphertext)
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.Unmarshal(plaintext, &body); err != nil {
		return nil, err
	}
	if m, ok := body["_method"]; ok {
		method, ok := m.(string)
		if !ok {
			return nil, errors.New("invalid _method")
		}
		upper := strings.ToUpper(method)
		if upper != "GET" && upper != "POST" && upper != "DELETE" {
			return nil, errors.New("invalid _method")
		}
		body["_method"] = upper
	}
	return body, nil
}

func parseBackend(body map[string]any) *session.Backend {
	raw, ok := body["backend"].(map[string]any)
	if !ok {
		return nil
	}
	btype, _ := raw["type"].(string)
	if btype == "" {
		return nil
	}
	port := 22
	if p, ok := raw["port"].(float64); ok {
		port = int(p)
	}
	connectionID, _ := raw["connectionId"].(string)
	if connectionID != "" && ssh.ValidateConnectionID(connectionID) != nil {
		connectionID = ""
	}
	host, _ := raw["host"].(string)
	user, _ := raw["user"].(string)
	hostname, _ := raw["hostname"].(string)
	if host != "" || user != "" {
		if err := ssh.ValidateParams(host, user, port); err != nil {
			return nil
		}
	}
	return &session.Backend{
		Type:         btype,
		ConnectionID: connectionID,
		Host:         host,
		User:         user,
		Port:         port,
		Hostname:     hostname,
	}
}

func (h *Handler) rateAllow(key string, limit int, window time.Duration) bool {
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	if now.Sub(h.lastRateSweep) > time.Minute {
		h.lastRateSweep = now
		for k, ts := range h.rateLimits {
			keep := false
			for _, t := range ts {
				if t.After(cutoff) {
					keep = true
					break
				}
			}
			if !keep {
				delete(h.rateLimits, k)
			}
		}
	}
	var valid []time.Time
	for _, t := range h.rateLimits[key] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	h.rateLimits[key] = valid
	return len(valid) <= limit
}

// --- SSH endpoints ---

func (h *Handler) handleSSHConnections(w http.ResponseWriter, r *http.Request, body map[string]any, method string) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available on server"}, nil)
		return
	}
	if method == "GET" || body["connections"] == nil {
		conns := h.sshMgr.All()
		util.SendJSON(w, 200, conns, nil)
		return
	}
	if !h.rateAllow("ssh-connections-"+h.clientIP(r), 10, time.Minute) {
		util.SendJSON(w, 429, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	rawConns, ok := body["connections"].([]any)
	if !ok {
		util.SendJSON(w, 200, map[string]any{"error": "Invalid connections data"}, nil)
		return
	}
	for _, raw := range rawConns {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, _ := c["id"].(string)
		host, _ := c["host"].(string)
		user, _ := c["user"].(string)
		port := util.IntFromAny(c["port"])
		hasOurKey, _ := c["hasOurKey"].(bool)
		hostname, _ := c["hostname"].(string)
		if ssh.ValidateConnectionID(id) != nil {
			continue
		}
		if ssh.ValidateParams(host, user, port) != nil {
			continue
		}
		_ = h.sshMgr.Add(ssh.Connection{ID: id, Host: host, User: user, Port: port, HasOurKey: hasOurKey, Hostname: hostname})
	}
	util.SendJSON(w, 200, map[string]any{"success": true}, nil)
}

func (h *Handler) handleSSHConnectionDelete(w http.ResponseWriter, body map[string]any, path string) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available on server"}, nil)
		return
	}
	id := strings.TrimPrefix(path, "/api/ssh-connections/")
	if ssh.ValidateConnectionID(id) != nil {
		util.SendJSON(w, 200, map[string]any{"error": "Invalid connection ID"}, nil)
		return
	}
	conn := h.sshMgr.FindByID(id)
	if conn == nil {
		util.SendJSON(w, 200, map[string]any{"error": "Connection not found"}, nil)
		return
	}

	remoteKeyRemoved := false
	var remoteKeyError string
	if conn.HasOurKey {
		cleaned, reason := h.sshMgr.RemoveRemoteKey(id, conn.Host, conn.User, conn.Port)
		remoteKeyRemoved = cleaned
		if !cleaned {
			remoteKeyError = reason
		}
	}

	h.sshMgr.Delete(id)
	h.sshMgr.InvalidateRemoteCache(id)

	resp := map[string]any{"removed": true}
	if conn.HasOurKey {
		resp["remoteKeyRemoved"] = remoteKeyRemoved
		if remoteKeyError != "" {
			resp["remoteKeyError"] = remoteKeyError
		}
	}
	util.SendJSON(w, 200, resp, nil)
}

func (h *Handler) handleSSHProbe(w http.ResponseWriter, body map[string]any, r *http.Request) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available on server"}, nil)
		return
	}
	if !h.rateAllow("ssh-probe-"+h.clientIP(r), 10, time.Minute) {
		util.SendJSON(w, 200, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	host, _ := body["host"].(string)
	user, _ := body["user"].(string)
	port := 22
	if p, ok := body["port"].(float64); ok {
		port = int(p)
	}
	if err := ssh.ValidateParams(host, user, port); err != nil {
		util.SendJSON(w, 200, map[string]any{"error": err.Error()}, nil)
		return
	}

	result, err := h.sshMgr.Probe(host, user, port)
	if err != nil {
		util.SendJSON(w, 200, map[string]any{"error": "Probe failed"}, nil)
		return
	}
	util.SendJSON(w, 200, result, nil)
}

func (h *Handler) handleSSHSetup(w http.ResponseWriter, body map[string]any, r *http.Request) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available on server"}, nil)
		return
	}

	ip := h.clientIP(r)
	if !h.rateAllow("ssh-setup-"+ip, 10, time.Minute) {
		util.SendJSON(w, 200, map[string]any{"error": "Too many setup attempts", "code": "rate_limited"}, nil)
		return
	}

	host, _ := body["host"].(string)
	user, _ := body["user"].(string)
	port := 22
	if p, ok := body["port"].(float64); ok {
		port = int(p)
	}
	password, _ := body["password"].(string)
	if err := ssh.ValidateParams(host, user, port); err != nil {
		util.SendJSON(w, 200, map[string]any{"error": err.Error()}, nil)
		return
	}
	if password == "" {
		util.SendJSON(w, 200, map[string]any{"error": "Password required"}, nil)
		return
	}

	var connID string
	if conn := h.sshMgr.FindByHostUser(host, user, port); conn != nil {
		connID = conn.ID
	}
	if connID == "" {
		connID = util.NewUUID()
	}

	err := h.sshMgr.SetupKey(connID, host, user, port, password)
	if err != nil {
		var se *ssh.SetupError
		if errors.As(err, &se) {
			util.SendJSON(w, 200, map[string]any{"error": se.Msg, "code": se.Code}, nil)
		} else {
			util.SendJSON(w, 200, map[string]any{"error": "SSH setup failed", "code": "unknown"}, nil)
		}
		return
	}

	hostname, ok := h.sshMgr.ProbeWithKey(connID, host, user, port)
	if !ok {
		util.SendJSON(w, 200, map[string]any{"error": "Key installed but verification failed", "code": "verify_failed"}, nil)
		return
	}

	_ = h.sshMgr.Add(ssh.Connection{ID: connID, Host: host, User: user, Port: port, HasOurKey: true, Hostname: hostname})
	util.SendJSON(w, 200, map[string]any{"id": connID, "hostname": hostname, "keyReady": true, "hasOurKey": true}, nil)
}

func (h *Handler) handleSSHLs(w http.ResponseWriter, body map[string]any, r *http.Request) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available"}, nil)
		return
	}
	if !h.rateAllow("ssh-ls-"+h.clientIP(r), 10, time.Minute) {
		util.SendJSON(w, 200, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	connID, _ := body["connectionId"].(string)
	remotePath, _ := body["path"].(string)
	if connID == "" {
		util.SendJSON(w, 200, map[string]any{"error": "connectionId required"}, nil)
		return
	}

	conn := h.sshMgr.FindByID(connID)
	if conn == nil {
		util.SendJSON(w, 200, map[string]any{"error": "Connection not found"}, nil)
		return
	}

	folders, err := h.sshMgr.ListRemote(connID, conn.Host, conn.User, conn.Port, remotePath)
	if err != nil {
		util.SendJSON(w, 200, map[string]any{"error": err.Error(), "folders": []string{}}, nil)
		return
	}
	parent := "/"
	if remotePath != "/" && remotePath != "" {
		trimmed := strings.TrimRight(remotePath, "/")
		idx := strings.LastIndex(trimmed, "/")
		if idx > 0 {
			parent = trimmed[:idx]
		}
	}
	util.SendJSON(w, 200, map[string]any{"path": remotePath, "parent": parent, "folders": folders}, nil)
}

func (h *Handler) handleSSHWhich(w http.ResponseWriter, body map[string]any, r *http.Request) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available"}, nil)
		return
	}
	if !h.rateAllow("ssh-which-"+h.clientIP(r), 10, time.Minute) {
		util.SendJSON(w, 200, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	connID, _ := body["connectionId"].(string)
	q, _ := body["q"].(string)
	if connID == "" {
		util.SendJSON(w, 200, map[string]any{"error": "connectionId required"}, nil)
		return
	}

	conn := h.sshMgr.FindByID(connID)
	if conn == nil {
		util.SendJSON(w, 200, map[string]any{"error": "Connection not found"}, nil)
		return
	}

	matches, err := h.sshMgr.SearchRemoteBinaries(connID, conn.Host, conn.User, conn.Port, q)
	if err != nil {
		util.SendJSON(w, 200, map[string]any{"matches": []string{}}, nil)
		return
	}
	util.SendJSON(w, 200, map[string]any{"matches": matches}, nil)
}

func (h *Handler) clientIP(r *http.Request) string {
	return util.ClientIP(r, h.cfg.TrustProxy)
}
