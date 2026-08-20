// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// SSH remote operations: probe, key setup, remote ls/which. Extracted from ssh.go.
package ssh

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"shells/internal/pty"
	"shells/internal/session"
	"shells/internal/util"
)

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

type remoteCacheEntry struct {
	binaries []string
	ts       time.Time
}

const remoteCacheTTL = 5 * time.Minute

const maxRemoteResults = 100

// randomMarker generates a unique marker string for probe output parsing.
func randomMarker() string {
	b := make([]byte, 8)
	_, _ = cryptorand.Read(b)
	return "SHELLS_PROBE_" + hex.EncodeToString(b)
}

// sanitizeRemotePath sanitizes a remote path by removing control characters
// and resolving . and .. components. Returns a path starting with /.
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

// parseProbeOutput extracts the hostname from probe output by finding the marker.
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

// errToString converts an error to its string representation, or empty string if nil.
func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// prefixFilter filters a sorted string slice to entries starting with prefix,
// limiting results to maxRemoteResults.
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

// validateResult reports the outcome of a remote cwd/command validation.
type validateResult int

const (
	validateOK validateResult = iota
	validateCwdBad
	validateCmdBad
	validateConnError
)

// ValidateRemote checks, in ONE ssh round-trip, that the remote cwd exists
// (test -d) and/or that a bare command resolves (command -v). Returns
// validateConnError when ssh itself fails — never blocks a spawn.
func (m *Manager) ValidateRemote(connID, host, user string, port int, cwd, command string) (validateResult, error) {
	if err := ValidateConnectionID(connID); err != nil {
		return validateConnError, err
	}
	m.probeSem <- struct{}{}
	defer func() { <-m.probeSem }()
	keyPath := filepath.Join(m.cfg.SSHKeysDir, connID)

	var parts []string
	if cwd != "" {
		parts = append(parts, fmt.Sprintf("test -d %s || exit 10", shellEscape(cwd)))
	}
	if command != "" && !strings.ContainsAny(command, " \t/") {
		parts = append(parts, fmt.Sprintf("command -v %s >/dev/null 2>&1 || exit 11", shellEscape(command)))
	}
	if len(parts) == 0 {
		return validateOK, nil
	}

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
		remoteCommand(strings.Join(parts, "; ")),
	}

	out, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			switch ee.ExitCode() {
			case 10:
				return validateCwdBad, nil
			case 11:
				return validateCmdBad, nil
			}
		}
		return validateConnError, fmt.Errorf("ssh validate: %s", strings.TrimSpace(string(out)))
	}
	return validateOK, nil
}

// Validate returns a session.Manager.SSHValidate callback wired to
// ValidateRemote. It can be assigned directly in main.go.
func (m *Manager) Validate() func(backend *session.Backend, command, cwd string) (session.ValidateResult, error) {
	return func(backend *session.Backend, command, cwd string) (session.ValidateResult, error) {
		res, err := m.ValidateRemote(backend.ConnectionID, backend.Host, backend.User, backend.Port, cwd, command)
		if err != nil {
			return session.ValidateConnError, err
		}
		switch res {
		case validateCwdBad:
			return session.ValidateCwdBad, nil
		case validateCmdBad:
			return session.ValidateCmdBad, nil
		case validateConnError:
			return session.ValidateConnError, nil
		default:
			return session.ValidateOK, nil
		}
	}
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
