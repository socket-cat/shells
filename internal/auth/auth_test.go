// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package auth

import (
	"net/http/httptest"
	"testing"
)

func TestHasAllowedOrigin(t *testing.T) {
	s := NewStore("")
	for _, c := range []struct {
		name, host, origin, fwd string
		want                    bool
	}{
		{"same host with port", "h:8443", "https://h:8443", "", true},
		{"foreign origin", "h", "https://evil", "", false},
		{"absent origin", "h", "", "", true},
		{"forwarded host wins", "127.0.0.1:8081", "https://h", "h, proxy", true},
		{"forwarded host refuses foreign", "h", "https://h", "evil", false},
	} {
		r := httptest.NewRequest("GET", "/ws", nil)
		r.Host = c.host
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.fwd != "" {
			r.Header.Set("X-Forwarded-Host", c.fwd)
		}
		if got := s.HasAllowedOrigin(r); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
