// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package ssh manages SSH connections: key generation, connection
// persistence, and SSH process spawning via the pty package.
package ssh

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"shells/internal/config"
	"shells/internal/pty"
	"shells/internal/session"
	"shells/internal/util"
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

// ProbeResult is returned by Probe to indicate SSH connectivity status.
type ProbeResult struct {
	KeyReady    bool   `json:"keyReady,omitempty"`
	ID          string `json:"id,omitempty"`
	HasOurKey   bool   `json:"hasOurKey,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Unreachable bool   `json:"unreachable,omitempty"`
}

// SetupError carries a machine-readable code for the frontend.
type SetupError struct {
	Code string
	Msg  string
}

func (e *SetupError) Error() string { return e.Msg }

// Manager handles SSH connection persistence and key management.
type Manager struct {
	cfg         *config.Config
	mu          sync.Mutex
	connections []Connection

	cacheMu sync.Mutex
	cache   map[string]*remoteCacheEntry

	probeSem chan struct{} // bounds concurrent ssh child processes
}

type remoteCacheEntry struct {
	binaries []string
	ts       time.Time
}

const remoteCacheTTL = 5 * time.Minute

const sshProbeConcurrency = 6

const maxRemoteResults = 100

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
	tmp := m.cfg.SSHConnectionsFile + ".tmp"
	data, _ := json.MarshalIndent(m.connections, "", "  ")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.cfg.SSHConnectionsFile)
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

// --- helpers ---

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

// --- connection validation ---

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

// --- SSH probe / setup / remote operations ---

func randomMarker() string {
	b := make([]byte, 8)
	_, _ = cryptorand.Read(b)
	return "SHELLS_PROBE_" + hex.EncodeToString(b)
}

func sanitizeRemotePath(p string) string {
	if p == "" {
		return "/"
	}
	p = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, p)
	var resolved []string
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		resolved = append(resolved, part)
	}
	return "/" + strings.Join(resolved, "/")
}

func parseProbeOutput(output, marker string) string {
	lines := strings.Split(output, "\n")
	for i, l := range lines {
		if strings.Contains(l, marker) && i+1 < len(lines) {
			h := strings.TrimSpace(lines[i+1])
			if util.ValidHostname(h) {
				return h
			}
			break
		}
	}
	return ""
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

// Probe checks SSH connectivity to host. It first tries the default system
// keys (BatchMode). If that works, the user can connect with an existing key.
// Otherwise it reports reachability so the frontend can prompt for a password.
func (m *Manager) Probe(host, user string, port int) (*ProbeResult, error) {
	m.probeSem <- struct{}{}
	defer func() { <-m.probeSem }()
	marker := randomMarker()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=" + sshStrictness(),
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "PreferredAuthentications=publickey",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(port),
		fmt.Sprintf("%s@%s", user, host),
		remoteCommand(fmt.Sprintf("printf '%%s\\n%%s\\n' '%s' \"$(hostname -s)\"", marker)),
	}

	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	outputStr := string(out)

	if err == nil && strings.Contains(outputStr, marker) {
		hostname := parseProbeOutput(outputStr, marker)
		conn := m.findByHostUser(host, user, port)
		if conn != nil {
			if hostname != "" && conn.Hostname == "" {
				conn.Hostname = hostname
				_ = m.Add(*conn)
			}
			return &ProbeResult{KeyReady: true, ID: conn.ID, HasOurKey: conn.HasOurKey, Hostname: conn.Hostname}, nil
		}
		id := util.NewUUID()
		_ = m.Add(Connection{ID: id, Host: host, User: user, Port: port, HasOurKey: false, Hostname: hostname})
		return &ProbeResult{KeyReady: true, ID: id, HasOurKey: false, Hostname: hostname}, nil
	}

	combined := strings.ToLower(outputStr + " " + errToString(err))
	if strings.Contains(combined, "permission denied") || strings.Contains(combined, "publickey") {
		return &ProbeResult{KeyReady: false}, nil
	}
	return &ProbeResult{Unreachable: true}, nil
}

// ProbeWithKey checks if our installed key works for the connection.
func (m *Manager) ProbeWithKey(connID, host, user string, port int) (string, bool) {
	keyPath := filepath.Join(m.cfg.SSHKeysDir, connID)
	if _, err := os.Stat(keyPath); err != nil {
		return "", false
	}
	marker := randomMarker()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []string{
		"-i", keyPath,
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=" + sshStrictness(),
		"-o", "UserKnownHostsFile=" + keyPath + ".known_hosts",
		"-o", "PreferredAuthentications=publickey",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(port),
		fmt.Sprintf("%s@%s", user, host),
		remoteCommand(fmt.Sprintf("printf '%%s\\n%%s\\n' '%s' \"$(hostname -s)\"", marker)),
	}

	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	if err != nil || !strings.Contains(string(out), marker) {
		return "", false
	}
	return parseProbeOutput(string(out), marker), true
}

// SetupKey installs our public key on the remote host using a password.
// It spawns ssh in a PTY, detects the password prompt, and feeds the password.
func (m *Manager) SetupKey(connID, host, user string, port int, password string) error {
	if err := GenerateKeyPair(m.cfg.SSHKeysDir, connID); err != nil {
		return &SetupError{Code: "install_failed", Msg: "Key generation failed"}
	}
	keyPath := filepath.Join(m.cfg.SSHKeysDir, connID)

	pubKey, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return &SetupError{Code: "install_failed", Msg: "Cannot read public key"}
	}
	pubKeyLine := strings.TrimSpace(string(pubKey))

	escapedKey := strings.ReplaceAll(pubKeyLine, "'", "'\\''")
	remoteCmd := fmt.Sprintf("umask 077 && mkdir -p ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys", escapedKey)

	args := []string{
		"-o", "StrictHostKeyChecking=" + sshStrictness(),
		"-o", "UserKnownHostsFile=" + keyPath + ".known_hosts",
		"-o", "PreferredAuthentications=password,keyboard-interactive",
		"-o", "PubkeyAuthentication=no",
		"-o", "NumberOfPasswordPrompts=3",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(port),
		fmt.Sprintf("%s@%s", user, host),
		remoteCommand(remoteCmd),
	}

	env := buildSSHEnv()
	term, err := pty.Spawn("ssh", args, env, "", 40, 10)
	if err != nil {
		return &SetupError{Code: "install_failed", Msg: "Cannot start ssh"}
	}

	resultCh := make(chan error, 1)
	var output []byte
	var mu sync.Mutex
	passwordTried := false

	cancelData := term.OnData(func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		output = append(output, data...)
		s := string(output)

		if strings.Contains(s, "yes/no") || strings.Contains(s, "(yes/no") {
			_, _ = term.Write([]byte("yes\n"))
			output = nil
			return
		}

		lower := strings.ToLower(s)
		if strings.Contains(lower, "password:") || strings.Contains(lower, "password for") {
			_, _ = term.Write([]byte(password + "\n"))
			passwordTried = true
			output = nil
		}
	})

	cancelExit := term.OnExit(func(exitCode int, signal string) {
		if exitCode == 0 {
			resultCh <- nil
		} else if passwordTried {
			resultCh <- &SetupError{Code: "max_attempts", Msg: "The password was incorrect"}
		} else {
			resultCh <- &SetupError{Code: "install_failed", Msg: fmt.Sprintf("Key installation failed (exit %d)", exitCode)}
		}
	})

	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	select {
	case err := <-resultCh:
		cancelData()
		cancelExit()
		return err
	case <-timer.C:
		cancelData()
		cancelExit()
		_ = term.Kill()
		return &SetupError{Code: "timeout", Msg: "Connection timed out"}
	}
}

// ListRemote lists folders in a remote directory via SSH with our key.
func (m *Manager) ListRemote(connID, host, user string, port int, remotePath string) ([]string, error) {
	m.probeSem <- struct{}{}
	defer func() { <-m.probeSem }()
	if err := ValidateConnectionID(connID); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(m.cfg.SSHKeysDir, connID)
	safePath := sanitizeRemotePath(remotePath)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	args := []string{
		"-i", keyPath,
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=" + sshStrictness(),
		"-o", "UserKnownHostsFile=" + keyPath + ".known_hosts",
		"-o", "PreferredAuthentications=publickey",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(port),
		fmt.Sprintf("%s@%s", user, host),
		remoteCommand("ls -1p " + shellEscape(safePath)),
	}

	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ssh ls: %s", strings.TrimSpace(string(out)))
	}

	var folders []string
	for _, entry := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.HasSuffix(entry, "/") {
			folders = append(folders, strings.TrimSuffix(entry, "/"))
		}
	}
	sort.Strings(folders)
	return folders, nil
}

// SearchRemoteBinaries returns remote command names matching a prefix.
// Results are cached per connection for 5 minutes.
func (m *Manager) SearchRemoteBinaries(connID, host, user string, port int, prefix string) ([]string, error) {
	m.probeSem <- struct{}{}
	defer func() { <-m.probeSem }()
	if err := ValidateConnectionID(connID); err != nil {
		return nil, err
	}

	m.cacheMu.Lock()
	entry, ok := m.cache[connID]
	if ok && time.Since(entry.ts) < remoteCacheTTL {
		bins := entry.binaries
		m.cacheMu.Unlock()
		return prefixFilter(bins, prefix), nil
	}
	m.cacheMu.Unlock()

	keyPath := filepath.Join(m.cfg.SSHKeysDir, connID)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	args := []string{
		"-i", keyPath,
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=" + sshStrictness(),
		"-o", "UserKnownHostsFile=" + keyPath + ".known_hosts",
		"-o", "PreferredAuthentications=publickey",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(port),
		fmt.Sprintf("%s@%s", user, host),
		// bash -i sources ~/.bashrc so compgen sees user binaries (cline etc.);
		// on bash-less hosts bash is simply absent and the empty result is
		// graceful. </dev/null + 2>/dev/null keep stdin and stderr clean.
		remoteCommand(`bash -i -c 'compgen -c' </dev/null 2>/dev/null`),
	}

	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	var binaries []string
	if err == nil {
		seen := make(map[string]bool)
		for _, name := range strings.Fields(string(out)) {
			if name != "" && !seen[name] {
				seen[name] = true
				binaries = append(binaries, name)
			}
		}
		sort.Strings(binaries)
	}

	m.cacheMu.Lock()
	m.cache[connID] = &remoteCacheEntry{binaries: binaries, ts: time.Now()}
	m.cacheMu.Unlock()

	return prefixFilter(binaries, prefix), nil
}

// RemoveRemoteKey removes our public key from the remote authorized_keys.
func (m *Manager) RemoveRemoteKey(connID, host, user string, port int) (bool, string) {
	if err := ValidateConnectionID(connID); err != nil {
		return false, "invalid_id"
	}
	keyPath := filepath.Join(m.cfg.SSHKeysDir, connID)
	pubKeyPath := keyPath + ".pub"

	pubKey, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return false, "no_local_pub"
	}
	pubKeyLine := strings.TrimSpace(string(pubKey))
	if strings.ContainsAny(pubKeyLine, "\n\r") {
		return false, "invalid_pub"
	}
	if !strings.HasPrefix(pubKeyLine, "ssh-ed25519 ") {
		return false, "invalid_pub"
	}

	escapedLine := strings.ReplaceAll(pubKeyLine, "'", "'\\''")
	script := "set -e\n" +
		"ak=\"$HOME/.ssh/authorized_keys\"\n" +
		"if [ -L \"$ak\" ]; then echo \"ERR:SYMLINK\"; exit 1; fi\n" +
		"if [ ! -f \"$ak\" ]; then echo \"ERR:NOFILE\"; exit 1; fi\n" +
		"tmp=$(mktemp \"$ak.XXXXXX\") || { echo \"ERR:TMP\"; exit 1; }\n" +
		fmt.Sprintf("grep -vFx -- '%s' \"$ak\" > \"$tmp\" || { rc=$?; if [ \"$rc\" -ne 1 ]; then rm -f \"$tmp\"; echo \"ERR:GREP\"; exit 1; fi; }\n", escapedLine) +
		"mv -f \"$tmp\" \"$ak\"\n" +
		fmt.Sprintf("grep -cFx -- '%s' \"$ak\" || echo 0\n", escapedLine)
	script = remoteCommand(script)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []string{
		"-i", keyPath,
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=" + sshStrictness(),
		"-o", "UserKnownHostsFile=" + keyPath + ".known_hosts",
		"-o", "PreferredAuthentications=publickey",
		"-o", "LogLevel=ERROR",
		"-p", strconv.Itoa(port),
		fmt.Sprintf("%s@%s", user, host),
		script,
	}

	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		log.Printf("RemoveRemoteKey: %s", outStr)
		return false, "remote key removal failed"
	}
	if strings.HasPrefix(outStr, "ERR:") {
		log.Printf("RemoveRemoteKey: %s", outStr)
		return false, "remote key removal failed"
	}
	lines := strings.Split(outStr, "\n")
	remaining, err := strconv.Atoi(strings.TrimSpace(lines[len(lines)-1]))
	if err != nil {
		return false, "bad_output"
	}
	return remaining == 0, ""
}

// InvalidateRemoteCache clears the binary cache for a connection (or all).
func (m *Manager) InvalidateRemoteCache(connID string) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if connID != "" {
		delete(m.cache, connID)
	} else {
		m.cache = make(map[string]*remoteCacheEntry)
	}
}

// --- helpers ---

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func prefixFilter(sorted []string, prefix string) []string {
	if prefix == "" {
		n := len(sorted)
		if n > maxRemoteResults {
			n = maxRemoteResults
		}
		out := make([]string, n)
		copy(out, sorted)
		return out
	}
	idx := sort.SearchStrings(sorted, prefix)
	var result []string
	for i := idx; i < len(sorted); i++ {
		if !strings.HasPrefix(sorted[i], prefix) {
			break
		}
		result = append(result, sorted[i])
		if len(result) >= maxRemoteResults {
			break
		}
	}
	return result
}
