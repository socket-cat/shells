// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"shells/internal/session"
	"shells/internal/util"
)

const (
	maxPasteImageBytes = 10 * 1024 * 1024 // 10 MB per file
	maxPasteDirBytes   = 50 * 1024 * 1024 // 50 MB total ring buffer cap
	maxPasteDirFiles   = 50               // 50 files cap
	pasteIDChars       = "abcdefghijklmnopqrstuvwxyz0123456789"
)

type pasteRecord struct {
	path    string
	backend *session.Backend // nil for local
}

var (
	pasteMu         sync.Mutex
	sessionPastes   = make(map[string][]pasteRecord) // sessionID -> []pasteRecord
	pasteHTTPClient = &http.Client{Timeout: 10 * time.Second}
)

// pasteDir returns the per-OS-user directory /tmp/s-<uid> for pasted images.
func pasteDir() string {
	return fmt.Sprintf("/tmp/s-%d", os.Getuid())
}

// securePasteDir refuses a paste dir another local user could control: /tmp is
// shared, so /tmp/s-<uid> may have been pre-created (or symlinked) by someone
// else to swap files before the CLI reads them.
func securePasteDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("unsafe paste dir %s", dir)
	}
	return os.Chmod(dir, 0700)
}

// pasteExt turns a client file name into a safe extension: ".[a-z0-9]{1,8}" or "".
func pasteExt(name string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	if ext == "" || len(ext) > 8 || !util.OnlyChars(ext, "abcdefghijklmnopqrstuvwxyz0123456789") {
		return ""
	}
	return "." + ext
}

// handlePasteImage receives an encrypted base64 file (any type) or image URL,
// validates size (URL fetches must be images), enforces the 50MB FIFO ring buffer, writes the file with mode 0600,
// tracks it by session ID, and returns the ultra-short path.
func (h *Handler) handlePasteImage(w http.ResponseWriter, r *http.Request, body map[string]any) {
	imgData, _ := body["image"].(string)
	imgURL, _ := body["url"].(string)

	var raw []byte
	var err error

	if imgData != "" {
		// Strip optional data URI scheme prefix (e.g., "data:image/png;base64,")
		if idx := strings.Index(imgData, ","); idx != -1 && strings.HasPrefix(imgData, "data:") {
			imgData = imgData[idx+1:]
		}

		// Decode base64 payload
		raw, err = base64.StdEncoding.DecodeString(imgData)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(imgData)
			if err != nil {
				util.SendJSON(w, 200, map[string]any{"error": "invalid base64 image data"}, nil)
				return
			}
		}
	} else if imgURL != "" {
		if !strings.HasPrefix(imgURL, "http://") && !strings.HasPrefix(imgURL, "https://") {
			util.SendJSON(w, 200, map[string]any{"error": "invalid image url scheme"}, nil)
			return
		}
		// SSRF safeguard: prevent fetching cloud instance metadata
		if strings.Contains(imgURL, "169.254.") || strings.Contains(imgURL, "metadata.google") {
			util.SendJSON(w, 200, map[string]any{"error": "prohibited image url host"}, nil)
			return
		}
		req, reqErr := http.NewRequestWithContext(r.Context(), "GET", imgURL, nil)
		if reqErr != nil {
			util.SendJSON(w, 200, map[string]any{"error": "invalid image url"}, nil)
			return
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 shells/image-paste")
		resp, fetchErr := pasteHTTPClient.Do(req)
		if fetchErr != nil {
			util.SendJSON(w, 200, map[string]any{"error": "failed to download image"}, nil)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			util.SendJSON(w, 200, map[string]any{"error": fmt.Sprintf("image download returned %d", resp.StatusCode)}, nil)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(resp.Body, maxPasteImageBytes+1))
		if err != nil {
			util.SendJSON(w, 200, map[string]any{"error": "failed to read image"}, nil)
			return
		}
	} else {
		util.SendJSON(w, 200, map[string]any{"error": "empty image"}, nil)
		return
	}

	if len(raw) == 0 {
		util.SendJSON(w, 200, map[string]any{"error": "empty image"}, nil)
		return
	}
	if len(raw) > maxPasteImageBytes {
		util.SendJSON(w, 200, map[string]any{"error": "file too large (max 10MB)"}, nil)
		return
	}

	// Magic bytes name images; uploads may be any type and prefer the client's
	// (cleaned) extension. URL fetches must be images.
	ext := ""
	switch mime := http.DetectContentType(raw); {
	case strings.HasPrefix(mime, "image/png"):
		ext = ".png"
	case strings.HasPrefix(mime, "image/jpeg"):
		ext = ".jpg"
	case strings.HasPrefix(mime, "image/webp"):
		ext = ".webp"
	case strings.HasPrefix(mime, "image/gif"):
		ext = ".gif"
	}
	if name, _ := body["name"].(string); imgData != "" && pasteExt(name) != "" {
		ext = pasteExt(name)
	} else if imgData == "" && ext == "" {
		util.SendJSON(w, 200, map[string]any{"error": "unsupported image format"}, nil)
		return
	}

	id := randomPasteID(4)
	sid, _ := body["sessionId"].(string)

	// Check if this session is remote SSH
	var remoteBackend *session.Backend
	if sid != "" && h.manager != nil {
		if s := h.manager.Get(sid); s != nil && s.Backend != nil && s.Backend.Type == "ssh" {
			remoteBackend = s.Backend
		}
	}

	if remoteBackend != nil && h.sshMgr != nil {
		user := remoteBackend.User
		if !util.OnlyChars(user, util.Alnum+"_.-") || user == "" {
			user = "remote"
		}
		remoteDir := fmt.Sprintf("/tmp/s-%s", user)
		remotePath := fmt.Sprintf("%s/%s%s", remoteDir, id, ext)

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		if err := h.sshMgr.WriteRemoteFile(ctx, remoteBackend, remotePath, raw); err != nil {
			util.SendJSON(w, 200, map[string]any{"error": "failed to save remote file: " + err.Error()}, nil)
			return
		}

		pasteMu.Lock()
		sessionPastes[sid] = append(sessionPastes[sid], pasteRecord{path: remotePath, backend: remoteBackend})
		pasteMu.Unlock()

		util.SendJSON(w, 200, map[string]any{"path": remotePath}, nil)
		return
	}

	// Local session
	dir := pasteDir()
	if err := os.MkdirAll(dir, 0700); err != nil || securePasteDir(dir) != nil {
		util.SendJSON(w, 200, map[string]any{"error": "failed to prepare storage"}, nil)
		return
	}

	pasteMu.Lock()
	defer pasteMu.Unlock()

	// Enforce Tier 1 FIFO eviction before write
	evictOldest(dir, int64(len(raw)))

	var path string
	var f *os.File
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, id+ext)
		f, err = os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			path = candidate
			break
		}
		id = randomPasteID(4)
	}
	if f == nil {
		util.SendJSON(w, 200, map[string]any{"error": "failed to generate unique file"}, nil)
		return
	}
	defer f.Close()

	if _, err := f.Write(raw); err != nil {
		_ = os.Remove(path)
		util.SendJSON(w, 200, map[string]any{"error": "failed to save file"}, nil)
		return
	}

	// Track for session-bound cleanup
	if sid != "" {
		sessionPastes[sid] = append(sessionPastes[sid], pasteRecord{path: path})
	}

	util.SendJSON(w, 200, map[string]any{"path": path}, nil)
}

func randomPasteID(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%04x", time.Now().UnixNano()%0xffff)[:length]
	}
	for i := range b {
		b[i] = pasteIDChars[int(b[i])%len(pasteIDChars)]
	}
	return string(b)
}

func evictOldest(dir string, incomingBytes int64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type fileInfo struct {
		name    string
		size    int64
		modTime time.Time
	}
	var files []fileInfo
	var totalSize int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{
			name:    e.Name(),
			size:    info.Size(),
			modTime: info.ModTime(),
		})
		totalSize += info.Size()
	}

	for i := 1; i < len(files); i++ {
		for j := i; j > 0 && files[j].modTime.Before(files[j-1].modTime); j-- {
			files[j], files[j-1] = files[j-1], files[j]
		}
	}

	for _, f := range files {
		if totalSize+incomingBytes <= maxPasteDirBytes && len(files) < maxPasteDirFiles {
			break
		}
		_ = os.Remove(filepath.Join(dir, f.name))
		totalSize -= f.size
		files = files[1:]
	}
}

// cleanupSessionPastes removes all image files uploaded during the given session.
func (h *Handler) cleanupSessionPastes(sessionID string) {
	pasteMu.Lock()
	records, ok := sessionPastes[sessionID]
	if ok {
		delete(sessionPastes, sessionID)
	}
	pasteMu.Unlock()
	if !ok {
		return
	}
	for _, rec := range records {
		if rec.backend != nil && rec.backend.Type == "ssh" && h.sshMgr != nil {
			go func(b *session.Backend, p string) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = h.sshMgr.RemoveRemoteFile(ctx, b, p)
			}(rec.backend, rec.path)
		} else {
			_ = os.Remove(rec.path)
		}
	}
}

// CleanupSessionPastes removes all local image files uploaded during the given session.
func CleanupSessionPastes(sessionID string) {
	pasteMu.Lock()
	defer pasteMu.Unlock()
	records, ok := sessionPastes[sessionID]
	if !ok {
		return
	}
	delete(sessionPastes, sessionID)
	for _, rec := range records {
		_ = os.Remove(rec.path)
	}
}

// SweepStalePastes removes all files in /tmp/s-<uid> older than maxAge.
func SweepStalePastes(maxAge time.Duration) {
	dir := pasteDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
