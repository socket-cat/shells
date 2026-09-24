// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package ssh manages SSH connections: key generation, connection
// persistence, and SSH process spawning via the pty package.
package ssh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"shells/internal/config"
	"shells/internal/fsutil"
	"shells/internal/pty"
	"shells/internal/session"
)

// Connection represents a saved SSH connection.
type Connection struct {
	ID        string `json:"id"`
	Host      string `json:"host"`
	User      string `json:"user"`
	Port      int    `json:"port"`
	Hostname  string `json:"hostname,omitempty"`
	HasOurKey bool   `json:"hasOurKey"`
}

// Manager handles SSH connection persistence and key management.
type Manager struct {
	cfg         *config.Config
	mu          sync.Mutex
	connections []Connection

	cacheMu sync.Mutex
	cache   map[string]*remoteCacheEntry

	probeSem chan struct{} // bounds concurrent ssh child processes
}

const sshProbeConcurrency = 6

// NewManager creates an SSH manager and loads persisted connections.
func NewManager(cfg *config.Config) *Manager {
	m := &Manager{cfg: cfg, cache: make(map[string]*remoteCacheEntry), probeSem: make(chan struct{}, sshProbeConcurrency)}
	m.reload()
	return m
}

func (m *Manager) reload() {
	raw, err := os.ReadFile(m.cfg.SSHConnectionsFile)
	if err != nil {
		return
	}
	_ = json.Unmarshal(raw, &m.connections)
	m.cleanupOrphanedKeys()
}

func (m *Manager) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.cfg.SSHConnectionsFile), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(m.connections, "", "  ")
	return fsutil.AtomicWrite(m.cfg.SSHConnectionsFile, data)
}

// All returns a snapshot of all saved connections.
func (m *Manager) All() []Connection {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Connection, len(m.connections))
	copy(out, m.connections)
	return out
}

// Add saves a new or updated connection.
func (m *Manager) Add(c Connection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.connections {
		if m.connections[i].ID == c.ID {
			m.connections[i] = c
			return m.saveLocked()
		}
	}
	m.connections = append(m.connections, c)
	return m.saveLocked()
}

// Delete removes a connection and its key files.
func (m *Manager) Delete(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := -1
	for i, c := range m.connections {
		if c.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	m.connections = append(m.connections[:idx], m.connections[idx+1:]...)
	deleteKeyFiles(m.cfg.SSHKeysDir, id)
	_ = m.saveLocked()
	return true
}

// FindByID returns a copy of the connection with the given ID, or nil.
// Safe to call concurrently (internal lock, value copy).
func (m *Manager) FindByID(id string) *Connection {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.connections {
		if m.connections[i].ID == id {
			cp := m.connections[i]
			return &cp
		}
	}
	return nil
}

// FindByHostUser returns a copy of the connection matching host+user+port,
// or nil. Safe to call concurrently (internal lock, value copy).
func (m *Manager) FindByHostUser(host, user string, port int) *Connection {
	return m.findByHostUser(host, user, port)
}

// findByHostUser returns a copy of the connection matching host+user+port.
func (m *Manager) findByHostUser(host, user string, port int) *Connection {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.connections {
		if m.connections[i].Host == host && m.connections[i].User == user && m.connections[i].Port == port {
			cp := m.connections[i]
			return &cp
		}
	}
	return nil
}

// Spawn creates a PTY-backed SSH session.  It matches the session.Manager's
// SpawnSSH callback signature so main.go can assign it directly.
func Spawn(cfg *config.Config) func(backend *session.Backend, cols, rows int, command, cwd string) (*pty.Term, string, string, error) {
	return func(backend *session.Backend, cols, rows int, command, cwd string) (*pty.Term, string, string, error) {
		if !hasSSH() {
			return nil, "", "", errors.New("ssh not available")
		}
		args := []string{"-t"}
		args = append(args, sshArgs(cfg.SSHKeysDir, backend.ConnectionID)...)
		args = append(args,
			"-o", "ServerAliveInterval=60",
			"-o", "ServerAliveCountMax=3",
			"-p", fmt.Sprintf("%d", backend.Port),
			fmt.Sprintf("%s@%s", backend.User, backend.Host),
		)
		if command != "" && cwd != "" {
			// cd failures exit loudly instead of silently dropping to $HOME.
			args = append(args, remoteCommand(fmt.Sprintf("cd %s || exit 1; %s%s", shellEscape(cwd), pathBootstrap, command)))
		} else if command != "" {
			args = append(args, remoteCommand(pathBootstrap+command))
		} else if cwd != "" {
			args = append(args, remoteCommand(fmt.Sprintf("cd %s || exit 1; exec $SHELL -l", shellEscape(cwd))))
		}
		env := buildSSHEnv()
		term, err := pty.Spawn("ssh", args, env, "", cols, rows)
		if err != nil {
			return nil, "", "", fmt.Errorf("ssh spawn: %w", err)
		}
		title := fmt.Sprintf("ssh: %s@%s", backend.User, backend.Host)
		if backend.Hostname != "" {
			title = "ssh: " + backend.Hostname
		}
		return term, "", title, nil
	}
}

// pathCapture prints the remote user's interactive PATH — the PATH an
// interactive shell would have, including ~/.bashrc additions like
// npm-global (where user binaries such as cline live). It tries bash first
// (Linux/macOS, and FreeBSD when bash is installed via pkg); bash is absent
// from FreeBSD's base install, so on a stock FreeBSD box the capture falls
// back to the user's login shell ($SHELL) which on FreeBSD reads ~/.cshrc
// unconditionally. </dev/null prevents a profile that reads stdin from
// consuming the user's PTY input; 2>/dev/null silences job-control notices;
// the marker + sed -n keeps only the PATH line so a profile that prints to
// stdout cannot corrupt it. Pure POSIX sh (no arrays, no here-strings):
// safe under /bin/sh (ash on FreeBSD, dash on Debian).
const pathCapture = `p=$(bash -i -c 'printf "__SHELLS_PATH__%s" "$PATH"' </dev/null 2>/dev/null | sed -n 's/.*__SHELLS_PATH__//p'); [ -n "$p" ] || p=$(${SHELL:-/bin/sh} -i -c 'printf "__SHELLS_PATH__%s" "$PATH"' </dev/null 2>/dev/null | sed -n 's/.*__SHELLS_PATH__//p'); printf %s "$p"`

// pathBootstrap sets PATH to the captured interactive value before running
// the user's command, so user binaries resolve. If the capture is empty
// (bash and $SHELL both fail) the existing sshd PATH is kept untouched; the
// ${PATH:-...} fallback only fires if PATH is somehow empty. Ends with "; "
// and no exec: the command runs as the last command of the remote shell, so
// compound commands ("a; b", "a && b", "for ...; done") work and the shell
// exits with the command's exit status.
const pathBootstrap = `p=$(` + pathCapture + `); [ -n "$p" ] && PATH=$p; export PATH="${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"; `

// remoteCommand wraps a remote shell payload so that it executes under
// /bin/sh no matter what the remote user's login shell is. sshd hands the
// string to the login shell with -c, and on a stock FreeBSD that shell is
// csh/tcsh, which rejects POSIX syntax ($(), export, arrays). The payload
// is therefore octal-encoded into a single-quoted /bin/sh -c argument: the
// resulting string contains only '\' and digits, which csh, tcsh, sh, ash,
// bash and zsh all pass through verbatim, and /bin/sh decodes and evals the
// real command. Single quotes in the payload are preserved, so this also
// fixes paths and commands containing quotes, $, backticks or '!'.
func remoteCommand(payload string) string {
	var sb strings.Builder
	sb.WriteString(`/bin/sh -c 'eval "$(printf %b "`)
	for i := 0; i < len(payload); i++ {
		fmt.Fprintf(&sb, `\%03o`, payload[i])
	}
	sb.WriteString(`")"'`)
	return sb.String()
}

func hasSSH() bool {
	_, err := exec.LookPath("ssh")
	return err == nil
}

func hasSSHKeygen() bool {
	_, err := exec.LookPath("ssh-keygen")
	return err == nil
}

func sshArgs(keysDir, connectionID string) []string {
	var args []string
	if connectionID != "" {
		keyPath := filepath.Join(keysDir, connectionID)
		if _, err := os.Stat(keyPath); err == nil {
			args = append(args, "-i", keyPath)
		}
		knownHosts := keyPath + ".known_hosts"
		args = append(args, "-o", "UserKnownHostsFile="+knownHosts)
	} else {
		args = append(args, "-o", "UserKnownHostsFile=/dev/null")
	}
	args = append(args,
		"-o", "StrictHostKeyChecking="+sshStrictness(),
		"-o", "PreferredAuthentications=publickey",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=15",
	)
	return args
}

var sshStrictnessCached string
var sshStrictnessOnce sync.Once

func sshStrictness() string {
	sshStrictnessOnce.Do(func() {
		out, err := exec.Command("ssh", "-V").CombinedOutput()
		if err != nil {
			sshStrictnessCached = "no"
			return
		}
		re := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)
		m := re.FindStringSubmatch(string(out))
		if m == nil {
			sshStrictnessCached = "no"
			return
		}
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		if major > 7 || (major == 7 && minor >= 6) {
			sshStrictnessCached = "accept-new"
		} else {
			sshStrictnessCached = "no"
		}
	})
	return sshStrictnessCached
}

func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func buildSSHEnv() []string {
	env := []string{
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
	}
	for _, key := range []string{"HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME"} {
		if val := os.Getenv(key); val != "" {
			env = append(env, key+"="+val)
		}
	}
	return env
}

var (
	hostRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.\-]*$`)
	ipRe   = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	userRe = regexp.MustCompile(`^[a-zA-Z0-9_.\-]+$`)
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidateParams checks SSH host/user/port.
func ValidateParams(host, user string, port int) error {
	if host == "" || len(host) > 253 {
		return errors.New("invalid host")
	}
	if !hostRe.MatchString(host) && !ipRe.MatchString(host) {
		return errors.New("invalid host format")
	}
	if user == "" || len(user) > 32 {
		return errors.New("invalid username")
	}
	if !userRe.MatchString(user) {
		return errors.New("invalid username format")
	}
	if port < 1 || port > 65535 {
		return errors.New("port must be 1-65535")
	}
	return nil
}

// ValidateConnectionID checks a UUID-formatted connection ID.
func ValidateConnectionID(id string) error {
	if !uuidRe.MatchString(strings.ToLower(id)) {
		return errors.New("invalid connection ID")
	}
	return nil
}

// GenerateKeyPair creates an ED25519 SSH key pair.
func GenerateKeyPair(keysDir, connectionID string) error {
	if err := ValidateConnectionID(connectionID); err != nil {
		return err
	}
	keyPath := filepath.Join(keysDir, connectionID)
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(keyPath); err == nil {
		return nil
	}
	if !hasSSHKeygen() {
		return errors.New("ssh-keygen not available")
	}
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", keyPath, "-N", "", "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-keygen: %w: %s", err, strings.TrimSpace(string(out)))
	}
	_ = os.Chmod(keyPath, 0o600)
	_ = os.Chmod(keyPath+".pub", 0o644)
	return nil
}

func deleteKeyFiles(keysDir, connectionID string) {
	keyPath := filepath.Join(keysDir, connectionID)
	for _, suffix := range []string{"", ".pub", ".known_hosts"} {
		_ = os.Remove(keyPath + suffix)
	}
}

func (m *Manager) cleanupOrphanedKeys() {
	valid := make(map[string]bool)
	for _, c := range m.connections {
		valid[c.ID] = true
	}
	entries, err := os.ReadDir(m.cfg.SSHKeysDir)
	if err != nil {
		return
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		id := strings.TrimSuffix(strings.TrimSuffix(name, ".pub"), ".known_hosts")
		if seen[id] {
			continue
		}
		seen[id] = true
		if !valid[id] && uuidRe.MatchString(strings.ToLower(id)) {
			deleteKeyFiles(m.cfg.SSHKeysDir, id)
		}
	}
}
