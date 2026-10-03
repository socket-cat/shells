// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package config

import "testing"

func TestEnvTrue(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"1", true},
		{"true", true},
		{"on", true},
		{"TRUE", true},
		{"On", true},
		{" on ", true},
		{"1 ", true},
		{"0", false},
		{"false", false},
		{"off", false},
		{"yes", false},
		{"garbage", false},
	}
	for _, tc := range cases {
		if got := EnvTrue(tc.in); got != tc.want {
			t.Errorf("EnvTrue(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestConfigAddr(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"127.0.0.1", 2222, "127.0.0.1:2222"},
		{"0.0.0.0", 8080, "0.0.0.0:8080"},
		{"localhost", 2222, "localhost:2222"},
		{"::1", 2222, "[::1]:2222"},
		{"[::1]", 2222, "[::1]:2222"},
		{"", 2222, ":2222"},
	}
	for _, tc := range cases {
		c := &Config{Host: tc.host, Port: tc.port}
		if got := c.Addr(); got != tc.want {
			t.Errorf("Config{Host: %q, Port: %d}.Addr() = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

func TestHostResolution(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SHELLS_KEY_DIR", tmpDir)

	// Case 1: default when unset is 127.0.0.1
	t.Setenv("HOST", "")
	t.Setenv("SHELLS_HOST", "")
	cfg, err := Load("test")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("default Host = %q, want 127.0.0.1", cfg.Host)
	}

	// Case 2: generic HOST is ignored (tcsh/csh export HOST=<hostname>)
	t.Setenv("HOST", "0.0.0.0")
	cfg, err = Load("test")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("inherited HOST changed Host to %q, want 127.0.0.1", cfg.Host)
	}

	// Case 3: SHELLS_HOST env var
	t.Setenv("SHELLS_HOST", "192.168.1.100")
	cfg, err = Load("test")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Host != "192.168.1.100" {
		t.Errorf("SHELLS_HOST override = %q, want 192.168.1.100", cfg.Host)
	}
}

func TestFirstEnvInt(t *testing.T) {
	t.Setenv("A", "")
	t.Setenv("B", "")
	if got := FirstEnvInt([]string{"A", "B"}, 42); got != 42 {
		t.Errorf("FirstEnvInt default = %d, want 42", got)
	}

	t.Setenv("B", "99")
	if got := FirstEnvInt([]string{"A", "B"}, 42); got != 99 {
		t.Errorf("FirstEnvInt fallback = %d, want 99", got)
	}

	t.Setenv("A", "77")
	if got := FirstEnvInt([]string{"A", "B"}, 42); got != 77 {
		t.Errorf("FirstEnvInt first = %d, want 77", got)
	}
}

func TestCanonicalEnvsPrecedence(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SHELLS_KEY_DIR", tmpDir)

	// Defaults
	cfg, err := Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 2222 {
		t.Errorf("default Port = %d, want 2222", cfg.Port)
	}
	if cfg.MaxSessions != 200 {
		t.Errorf("default MaxSessions = %d, want 200", cfg.MaxSessions)
	}

	// Legacy/PaaS envs work
	t.Setenv("PORT", "3333")
	t.Setenv("SECRET", "legacy-secret")
	t.Setenv("MAX_SESSIONS", "150")
	cfg, err = Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 3333 || cfg.Secret != "legacy-secret" || cfg.MaxSessions != 150 {
		t.Errorf("legacy envs failed: port=%d, secret=%s, maxSessions=%d", cfg.Port, cfg.Secret, cfg.MaxSessions)
	}
	if cfg.SecretSource != "$SECRET" {
		t.Errorf("SecretSource = %q, want $SECRET", cfg.SecretSource)
	}

	// Canonical SHELLS_* take precedence over legacy
	t.Setenv("SHELLS_PORT", "4444")
	t.Setenv("SHELLS_SECRET", "canonical-secret")
	t.Setenv("SHELLS_MAX_SESSIONS", "120")
	cfg, err = Load("test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 4444 || cfg.Secret != "canonical-secret" || cfg.MaxSessions != 120 {
		t.Errorf("canonical envs failed: port=%d, secret=%s, maxSessions=%d", cfg.Port, cfg.Secret, cfg.MaxSessions)
	}
	if cfg.SecretSource != "$SHELLS_SECRET" {
		t.Errorf("SecretSource = %q, want $SHELLS_SECRET", cfg.SecretSource)
	}
}
