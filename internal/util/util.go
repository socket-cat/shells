// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package util provides small shared helpers used across the shells server:
// integer clamping, JSON responses (optionally encrypted), client-IP
// extraction, and prefix search.
package util

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"shells/internal/crypto"
)

// hostnameRE matches RFC-compliant hostnames (letters/digits/dots/hyphens,
// not starting/ending with a hyphen). Precompiled once at package load.
var hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// ValidHostname reports whether h is a plausible hostname. The 253-byte cap is
// the DNS limit — callers that validate strings derived from REMOTE input
// (e.g. a remote SSH server's hostname) rely on this length bound.
func ValidHostname(h string) bool {
	return h != "" && len(h) <= 253 && hostnameRE.MatchString(h)
}

// EncryptedWriter wraps an http.ResponseWriter and carries the session API key
// so that SendJSON can transparently encrypt the response body. Handlers set
// it during the auth/crypto middleware (mirrors res._apiKey in the JS app).
type EncryptedWriter struct {
	http.ResponseWriter
	APIKey []byte
}

// ClampInt clamps v to [min, max], returning fallback if v < min (used when
// the caller must keep a sensible minimum even for absurdly small input).
func ClampInt(v, fallback, min, max int) int {
	if v < min {
		return fallback
	}
	if v > max {
		return max
	}
	return v
}

// IntFromAny coerces a decoded JSON value to an int (float64, int, or
// json.Number from a UseNumber decoder), returning 0 otherwise.
func IntFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

// NewUUID returns a random RFC 4122 v4 UUID string.
func NewUUID() string {
	var b [16]byte
	_, _ = cryptorand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// SendJSON writes a JSON response. If status is 204 no body is written. If the
// ResponseWriter is an *EncryptedWriter with a non-nil APIKey the payload is
// AES-GCM encrypted (X-Shells-Encrypted: 1) to match the browser's
// decryptPayload path.
func SendJSON(w http.ResponseWriter, status int, payload any, extraHeaders map[string]string) {
	if status == 204 {
		for k, v := range extraHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(204)
		return
	}

	if ew, ok := w.(*EncryptedWriter); ok && ew.APIKey != nil {
		plaintext, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, `{"error":"JSON encode failed"}`, http.StatusInternalServerError)
			return
		}
		enc, err := crypto.EncryptApiPayload(ew.APIKey, plaintext)
		if err != nil {
			http.Error(w, `{"error":"Encryption failed"}`, http.StatusInternalServerError)
			return
		}
		body, _ := json.Marshal(enc)
		for k, v := range extraHeaders {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Shells-Encrypted", "1")
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"error":"JSON encode failed"}`, http.StatusInternalServerError)
		return
	}
	for k, v := range extraHeaders {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ClientIP extracts the client IP. Proxy headers (X-Real-IP, X-Forwarded-For)
// are honored ONLY when trustProxy is true (i.e. behind a configured reverse
// proxy); otherwise the socket remote address is used. This prevents clients
// from spoofing their IP to bypass rate limits.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if real := r.Header.Get("X-Real-IP"); real != "" {
			return strings.TrimSpace(real)
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx > 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host
}

// PrefixSearch returns up to limit names from list whose lowercase form starts
// with the lowercase prefix. An empty prefix yields no matches.
func PrefixSearch(list []string, prefix string, limit int) []string {
	if limit <= 0 {
		limit = 20
	}
	if prefix == "" {
		return nil
	}
	lower := strings.ToLower(prefix)
	matches := make([]string, 0, limit)
	for _, name := range list {
		if strings.HasPrefix(strings.ToLower(name), lower) {
			matches = append(matches, name)
			if len(matches) >= limit {
				break
			}
		}
	}
	return matches
}
