// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package auth implements the session-token store and request authentication
// (cookie / X-Shells-Token header validation, origin checking), using
// constant-time comparisons throughout.
package auth

import (
	"errors"
	"net/http"
	"strings"
	"sync"
)

const maxActiveTokens = 10000

// ErrTooManyTokens is returned by Register when the token store is full and
// no stale tokens could be reclaimed. Callers should reject the connection
// gracefully rather than crash.
var ErrTooManyTokens = errors.New("auth: too many active tokens")

type tokenEntry struct {
	apiKey []byte
	done   <-chan struct{} // closed when the owning WS connection terminates
}

// Store holds active session tokens and the app-level bootstrap token.
type Store struct {
	appToken string

	mu     sync.Mutex
	tokens map[string]*tokenEntry
}

// NewStore creates a token store. appToken is the static admin token
// (SHELLS_TOKEN) accepted before any WS handshake completes.
func NewStore(appToken string) *Store {
	return &Store{
		appToken: appToken,
		tokens:   make(map[string]*tokenEntry),
	}
}

// Register adds a session token tied to a WS connection's done channel. When
// the connection closes (done is closed) the token becomes stale and is
// eligible for cleanup. It returns ErrTooManyTokens if the store is full.
func (s *Store) Register(token string, done <-chan struct{}, apiKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tokens) >= maxActiveTokens {
		s.cleanupLocked()
		if len(s.tokens) >= maxActiveTokens {
			return ErrTooManyTokens
		}
	}
	s.tokens[token] = &tokenEntry{apiKey: apiKey, done: done}
	return nil
}

// Revoke removes a session token.
func (s *Store) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

// APIKeyForToken returns the API key associated with a session token, or nil.
func (s *Store) APIKeyForToken(token string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tokens[token]
	if !ok {
		return nil
	}
	return e.apiKey
}

// HasSessionToken reports whether token is a currently active session token.
func (s *Store) HasSessionToken(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tokens[token]
	return ok
}

// HasAllowedOrigin verifies that the request Origin (if present) matches the
// serving host, preventing cross-site WebSocket / fetch hijacking. It is
// reverse-proxy aware: when X-Forwarded-Host is present (set by nginx etc.)
// it takes precedence over the Host header, so deployments behind a proxy
// that preserves the original host are not falsely rejected. An absent Origin
// (non-browser clients) is always allowed.
func (s *Store) HasAllowedOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	// Extract hostname from origin URL.
	originHost := extractHost(origin)
	if originHost == "" {
		return false
	}

	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Header.Get("Host")
	}
	if host == "" {
		return false
	}
	// X-Forwarded-Host may be a comma-separated chain; the first entry is
	// the original client-requested host.
	if i := strings.Index(host, ","); i >= 0 {
		host = host[:i]
	}
	// Strip port from Host.
	colonIdx := strings.LastIndex(host, ":")
	hostName := host
	if colonIdx > 0 {
		hostName = host[:colonIdx]
	}

	return originHost == hostName
}

// Cleanup removes tokens whose WS connections have closed. Intended to be
// called periodically.
func (s *Store) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupLocked()
}

func (s *Store) cleanupLocked() int {
	cleaned := 0
	for token, e := range s.tokens {
		select {
		case <-e.done:
			delete(s.tokens, token)
			cleaned++
		default:
		}
	}
	return cleaned
}

// --- helpers ---

// extractHost pulls the hostname out of an Origin or URL string, handling
// scheme://host[:port] and host[:port] forms.
func extractHost(rawurl string) string {
	s := rawurl
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	// Strip brackets and port from [::1]:8080 or host:port.
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end >= 0 {
			return s[1:end]
		}
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}
