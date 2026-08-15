// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package branding holds the deployment-wide app name and accent color.
// Because it lives on the server, the served PWA manifest and icon reflect it,
// so the browser updates the installed app's name/icon on the OS when it
// changes (like code-server's --app-name).
package branding

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"

	"shells/internal/fsutil"
)

// State is the branding shown in the manifest, icon, and in-app UI.
type State struct {
	AppName string `json:"appName"`
	Accent  string `json:"accent"`
}

// Store is a concurrency-safe, file-backed branding holder.
type Store struct {
	mu   sync.RWMutex
	st   State
	path string // empty => in-memory only (no persistence)
}

var hexRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// ValidAccent reports whether s is a usable accent color (#rrggbb).
func ValidAccent(s string) bool { return hexRe.MatchString(s) }

// Load reads branding from path (if present), falling back to the provided
// defaults. path may be "" for an in-memory store.
func Load(path, defName, defAccent string) *Store {
	s := &Store{path: path, st: State{AppName: defName, Accent: defAccent}}
	if path == "" {
		return s
	}
	if data, err := os.ReadFile(path); err == nil {
		var v State
		if json.Unmarshal(data, &v) == nil {
			if strings.TrimSpace(v.AppName) != "" {
				s.st.AppName = strings.TrimSpace(v.AppName)
			}
			if ValidAccent(v.Accent) {
				s.st.Accent = v.Accent
			}
		}
	}
	return s
}

// Get returns a snapshot of the current branding.
func (s *Store) Get() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st
}

// Set updates the branding (validating + clamping) and persists it.
func (s *Store) Set(appName, accent string) error {
	s.mu.Lock()
	name := strings.TrimSpace(appName)
	if name == "" {
		name = s.st.AppName
	}
	if len(name) > 40 {
		name = name[:40]
	}
	if !ValidAccent(accent) {
		accent = s.st.Accent
	}
	s.st.AppName = name
	s.st.Accent = accent
	s.mu.Unlock()
	return s.persist()
}

func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	data, _ := json.MarshalIndent(s.st, "", "  ")
	path := s.path
	s.mu.RUnlock()
	return fsutil.AtomicWrite(path, data)
}
