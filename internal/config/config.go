// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package config resolves and holds all runtime configuration for the shells
// server: bind port, session limits, the derived cryptographic secret/salt,
// allowed shells, on-disk key directory, and SSH availability.
//
// On Load the package also initialises the crypto subsystem (server identity
// key, PBKDF2 secret-hash) so that the rest of the server can encrypt/decrypt
// immediately.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"shells/internal/crypto"
)

// Tunables (fixed).
const (
	KeepaliveIntervalMs  = 30000
	MaxClientsPerSession = 50
	OutputBufferMax      = 262144 // ~256KB ring buffer per session (pause/replay buffer)
	WSHWM                = 512 * 1024
	WSLWM                = 64 * 1024
	WSCWM                = 2048 * 1024
)

// ShellEnvKeys is the allowlist of environment variables inherited by spawned
// shells.
var ShellEnvKeys = []string{
	"HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME", "PATH", "PWD",
	"SHELL", "SHLVL", "TERM", "USER", "USERNAME",
}

// NonReplayableDecModes lists DEC private modes whose reset must not be
// replayed to late-joining clients (they clear the alternate screen etc.).
var NonReplayableDecModes = map[string]bool{
	"47": true, "1047": true, "1048": true, "1049": true,
}

// Config bundles every resolved setting.
type Config struct {
	Port                  int
	KeepaliveIntervalMs   int
	MaxSessions           int
	MaxClientsPerSession  int
	AppToken              string
	Secret                string
	SecretFile            string
	SecretSource          string
	Salt                  []byte
	SaltFile              string
	OutputBufferMax       int
	WSHWM                 int
	WSLWM                 int
	WSCWM                 int
	NonReplayableDecModes map[string]bool
	ShellEnvKeys          []string
	DefaultShell          string
	AllowedShells         []string
	// CheckOrigin, when true, enforces same-origin checks on WebSocket
	// upgrades and API requests (honor X-Forwarded-Host when behind a proxy).
	// Defaults to false so existing reverse-proxy deployments keep working.
	CheckOrigin        bool
	TrustProxy         bool
	TLS                bool
	Cwd                string
	Version            string
	ServerKeyDir       string
	ServerKeyFile      string
	RecentPathsFile    string
	RecentCommandsFile string
	SSHConnectionsFile string
	BrandingFile       string
	SSHKeysDir         string
	SSHAvailable       bool
	Accent             string
	AppName            string
	// UpdateCheck enables the self-update check (opt-out: SHELLS_UPDATE_CHECK=false).
	UpdateCheck bool
	// BinaryPath is the absolute path of the running binary, used to stage
	// ".new" updates next to it (override: SHELLS_BINARY_PATH).
	BinaryPath    string
	UpdateRepo    string
	UpdateSigURL  string
	UpdateAPIBase string
	// UpdateChecksumsURL and UpdateDownloadBase default to the GitHub "latest
	// download" URLs; overridable (loopback http allowed) for local e2e tests.
	UpdateChecksumsURL string
	UpdateDownloadBase string
}

// Load resolves all configuration from environment/files, creates the key
// directory and persisted secrets when absent, and initialises the crypto
// subsystem. version is the application version string (read from the embedded
// VERSION asset by the caller).
func Load(version string) (*Config, error) {
	binPath := os.Getenv("SHELLS_BINARY_PATH")
	if binPath == "" {
		if p, err := os.Executable(); err == nil {
			binPath = p
		}
	}
	updateRepo := firstNonEmpty(os.Getenv("SHELLS_UPDATE_REPO"), "socket-cat/shells")
	c := &Config{
		Port:                  envInt("PORT", 2222),
		KeepaliveIntervalMs:   KeepaliveIntervalMs,
		MaxSessions:           envInt("MAX_SESSIONS", 200),
		MaxClientsPerSession:  MaxClientsPerSession,
		OutputBufferMax:       OutputBufferMax,
		WSHWM:                 WSHWM,
		WSLWM:                 WSLWM,
		WSCWM:                 WSCWM,
		NonReplayableDecModes: NonReplayableDecModes,
		ShellEnvKeys:          ShellEnvKeys,
		CheckOrigin:           os.Getenv("SHELLS_CHECK_ORIGIN") == "true",
		TrustProxy:            os.Getenv("SHELLS_TRUST_PROXY") == "true",
		TLS:                   EnvTrue(os.Getenv("SHELLS_TLS")),
		Cwd:                   firstNonEmpty(os.Getenv("SHELLS_CWD"), homeDir()),
		Version:               version,
		Accent:                firstNonEmpty(os.Getenv("SHELLS_ACCENT"), "#fab283"),
		AppName:               firstNonEmpty(os.Getenv("SHELLS_APP_NAME"), "Shells"),
		UpdateCheck:           os.Getenv("SHELLS_UPDATE_CHECK") != "false",
		BinaryPath:            binPath,
		UpdateRepo:            updateRepo,
		UpdateSigURL:          firstNonEmpty(os.Getenv("SHELLS_UPDATE_SIG_URL"), "https://socket.cat/shells/checksums.txt.sig"),
		UpdateAPIBase:         firstNonEmpty(os.Getenv("SHELLS_UPDATE_API_BASE"), "https://api.github.com"),
		UpdateChecksumsURL:    firstNonEmpty(os.Getenv("SHELLS_UPDATE_CHECKSUMS_URL"), "https://github.com/"+updateRepo+"/releases/latest/download/checksums.txt"),
		UpdateDownloadBase:    firstNonEmpty(os.Getenv("SHELLS_UPDATE_DOWNLOAD_BASE"), "https://github.com/"+updateRepo+"/releases/latest/download/"),
	}

	if c.Cwd == "" {
		c.Cwd = "/"
	}

	// App token (random when not supplied via env).
	c.AppToken = firstNonEmpty(os.Getenv("SHELLS_TOKEN"), randomHex(24))

	// Key directory.
	c.ServerKeyDir = firstNonEmpty(
		os.Getenv("SHELLS_KEY_DIR"),
		filepath.Join(homeDir(), ".socket.cat", "config", "shells"),
	)
	if err := ensureDirMode(c.ServerKeyDir, 0o700); err != nil {
		return nil, fmt.Errorf("key dir %s: %w", c.ServerKeyDir, err)
	}

	c.ServerKeyFile = filepath.Join(c.ServerKeyDir, "server-key")
	c.RecentPathsFile = filepath.Join(c.ServerKeyDir, "recent-paths.json")
	c.RecentCommandsFile = filepath.Join(c.ServerKeyDir, "recent-commands.json")
	c.SecretFile = filepath.Join(c.ServerKeyDir, "secret.txt")
	c.SaltFile = filepath.Join(c.ServerKeyDir, "salt.txt")
	c.SSHConnectionsFile = filepath.Join(c.ServerKeyDir, "ssh-connections.json")
	c.BrandingFile = filepath.Join(c.ServerKeyDir, "branding.json")
	c.SSHKeysDir = filepath.Join(c.ServerKeyDir, "ssh-keys")

	// Resolve secret.
	secret, src, err := resolveSecret(c.SecretFile)
	if err != nil {
		return nil, err
	}
	c.Secret = secret
	c.SecretSource = src

	// Resolve salt (persisted, random when absent).
	salt, err := readOrCreateHex(c.SaltFile, 16)
	if err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	c.Salt = salt

	// SSH provisioning.
	c.SSHAvailable = true
	if err := ensureDirMode(c.SSHKeysDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "[SSH] Failed to initialize SSH keys directory: %v\n", err)
		c.SSHAvailable = false
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		fmt.Fprintf(os.Stderr, "[SSH] ssh not available (%v)\n", err)
		c.SSHAvailable = false
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		fmt.Fprintf(os.Stderr, "[SSH] ssh-keygen not available (%v)\n", err)
		c.SSHAvailable = false
	}

	// Shells.
	c.DefaultShell, c.AllowedShells = detectShells()

	if !validHexColor(c.Accent) {
		c.Accent = "#fab283"
	}

	// Initialise crypto (server identity + PBKDF2 secret hash).
	if err := crypto.Init([]byte(c.Secret), c.Salt, c.ServerKeyFile); err != nil {
		return nil, fmt.Errorf("crypto init: %w", err)
	}

	return c, nil
}

// --- helpers ---

func validHexColor(s string) bool {
	if len(s) != 7 || s[0] != '#' {
		return false
	}
	for _, c := range s[1:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// EnvTrue is the single shared parser for boolean env flags (SHELLS_TLS and
// friends), used by both the server and the selfupdate supervisor — the two
// must agree on what counts as enabled, or a flag like SHELLS_TLS=" on "
// would make the child and its preflight probe disagree. It reports whether v
// represents an enabled boolean flag: "1", "true", or "on" (case-insensitive,
// surrounding whitespace tolerated). Anything else is false.
func EnvTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on":
		return true
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return os.Getenv("HOME")
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// ensureDirMode creates dir (recursively) or, if it exists, re-asserts mode.
func ensureDirMode(dir string, mode os.FileMode) error {
	info, err := os.Stat(dir)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return os.Chmod(dir, mode)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.MkdirAll(dir, mode)
}

// exclusiveCreate writes content to path only if it does not already exist.
// Returns true when the file was newly created.
func exclusiveCreate(path string, content []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
}

// readOrCreateHex reads a hex-encoded file; if missing it generates n random
// bytes, persists them, and returns them. On a race it re-reads.
func readOrCreateHex(path string, n int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		return hex.DecodeString(strings.TrimSpace(string(raw)))
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	created, err := exclusiveCreate(path, []byte(hex.EncodeToString(b)))
	if err != nil {
		return nil, err
	}
	if created {
		return b, nil
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(raw)))
}

func resolveSecret(secretFile string) (string, string, error) {
	if env := os.Getenv("SECRET"); env != "" {
		return env, "env", nil
	}
	raw, err := os.ReadFile(secretFile)
	if err == nil {
		return strings.TrimSpace(string(raw)), "file", nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", "", err
	}
	gen := randomHex(16)
	created, err := exclusiveCreate(secretFile, []byte(gen))
	if err != nil {
		return "", "", err
	}
	if created {
		return gen, "generated", nil
	}
	raw, err = os.ReadFile(secretFile)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(raw)), "file", nil
}

func detectShells() (defaultShell string, allowed []string) {
	// Shells we offer, in preference order. exec.LookPath resolves each to its
	// full path wherever it lives on PATH — /bin/bash (Linux), /usr/local/bin/bash
	// (FreeBSD), /opt/homebrew/bin/bash (macOS) — so there's no hardcoded path
	// list to maintain.
	preference := []string{"bash", "sh", "zsh"}
	seen := make(map[string]bool)
	for _, name := range preference {
		if p, err := exec.LookPath(name); err == nil {
			if !seen[p] {
				seen[p] = true
				allowed = append(allowed, p)
			}
		}
	}

	// Default: an explicit SHELLS_DEFAULT_SHELL always wins. Otherwise take the
	// first shell found on PATH (bash on Linux/macOS, /bin/sh on a stock
	// FreeBSD system where bash is not in the base install). If PATH somehow
	// yields nothing, /bin/sh exists on every Unix.
	if env := os.Getenv("SHELLS_DEFAULT_SHELL"); env != "" {
		defaultShell = env
		if p, err := exec.LookPath(env); err == nil {
			defaultShell = p
		}
	} else if len(allowed) > 0 {
		defaultShell = allowed[0]
	} else {
		defaultShell = "/bin/sh"
	}

	if !seen[defaultShell] {
		allowed = append(allowed, defaultShell)
	}
	return defaultShell, allowed
}
