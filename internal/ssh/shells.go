// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Shells remotes: connections of kind "shells", reached over https with
// internal/federate where an ssh connection uses the ssh binary. Same list,
// same picker flow, the credential next to the keys (ssh-keys/<id>.shells).
package ssh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"shells/internal/config"
	"shells/internal/federate"
	"shells/internal/pty"
	"shells/internal/session"
	"shells/internal/util"
)

// SetupShells is SetupKey for a shells remote: the secret, used once like the
// SSH password, proves itself and becomes the stored credential; the
// remote's `hostname -s` becomes the label, as ProbeWithKey reads it.
func (m *Manager) SetupShells(rawURL string, secret []byte) (*Connection, error) {
	_, host, port, err := federate.NormalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	id := util.NewUUID()
	if c := m.FindByHostUser(host, "", port); c != nil && c.Kind == "shells" {
		id = c.ID
	}
	if err := federate.Setup(m.cfg.SSHKeysDir, id, rawURL, secret); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	hostname := ""
	if code, err := federate.Run(m.cfg.SSHKeysDir, id, "hostname -s", nil, &out, nil); err == nil && code == 0 {
		if h := strings.TrimSpace(out.String()); util.ValidHostname(h) {
			hostname = h
		}
	}
	c := Connection{ID: id, Kind: "shells", Host: host, Port: port, Hostname: hostname}
	return &c, m.Add(c)
}

// spawnShells is Spawn for a shells remote. The local server opens the
// remote session itself (the remote checks cwd and command, as ValidateRemote
// does for ssh), the PTY runs `shells connect <id> <sid> [marker]` the way it
// runs ssh -t, and the PTY's end deletes the remote session: the hangup sshd
// gives a dropped ssh client (Term.Kill is SIGKILL, and a shells remote
// keeps a detached session alive).
func spawnShells(cfg *config.Config, b *session.Backend, cols, rows int, command, cwd string) (*pty.Term, string, string, error) {
	sid, marker, err := federate.Open(cfg.SSHKeysDir, b.ConnectionID, cols, rows, cwd, command)
	var ae *federate.APIError
	switch {
	case errors.As(err, &ae) && ae.Code == "cwd_unusable":
		return nil, "", "", fmt.Errorf("%w: %q: not a directory", session.ErrCwdUnusable, cwd)
	case errors.As(err, &ae) && ae.Code == "command_not_found":
		return nil, "", "", fmt.Errorf("%w: %q", session.ErrCommandNotFound, command)
	case err != nil:
		return nil, "", "", fmt.Errorf("shells remote: %w", err)
	}
	self, err := os.Executable()
	if err == nil {
		args := []string{"connect", b.ConnectionID, sid}
		if marker != "" {
			args = append(args, marker)
		}
		var term *pty.Term
		if term, err = pty.Spawn(self, args, append(buildSSHEnv(), "SHELLS_KEY_DIR="+cfg.ServerKeyDir), "", cols, rows); err == nil {
			term.OnExit(func(int, string) { go federate.Delete(cfg.SSHKeysDir, b.ConnectionID, sid) })
			label := b.Host
			if b.Hostname != "" {
				label = b.Hostname
			}
			return term, "", "shells: " + label, nil
		}
	}
	federate.Delete(cfg.SSHKeysDir, b.ConnectionID, sid)
	return nil, "", "", fmt.Errorf("shells spawn: %w", err)
}

// ResolveShells finds the shells connection called name (its label, host,
// host:port, URL or id) in the connections list file, for the client
// commands, as ssh resolves a host.
func ResolveShells(file, name string) (string, error) {
	raw, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	var conns []Connection
	_ = json.Unmarshal(raw, &conns)
	var hits []string
	for _, c := range conns {
		hostPort := fmt.Sprintf("%s:%d", c.Host, c.Port)
		if c.Kind == "shells" && (name == c.ID || name == c.Hostname || name == c.Host || name == hostPort ||
			name == "https://"+c.Host || name == "https://"+hostPort) {
			hits = append(hits, c.ID)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no shells connection %q: add https://<host> in the picker first", name)
	case 1:
		return hits[0], nil
	}
	return "", fmt.Errorf("%q matches %d shells connections: use host:port or the id", name, len(hits))
}
