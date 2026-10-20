// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package federate is the transport for a shells remote: a connection of
// kind "shells" in the SSH connections list, reached over https the way the
// ssh package reaches a host with the ssh binary. Its credential (the remote
// secret's PBKDF2 hash plus the pinned identity and TLS leaf) lives next to
// the SSH keys as ssh-keys/<id>.shells. It is a client of the remote's
// existing /ws + /api protocol, so the remote needs no change
// (plans/federated-shells.md).
package federate

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"shells/internal/fsutil"
	"shells/internal/util"
)

const usage = "usage: shells                               the server, configured by SHELLS_* env (README)\n       shells exec <name> [--] <command>\n       shells connect <name>"

// Main runs a client command, like ssh does from a terminal: args[0] is
// "exec" or "connect", <name> a shells connection of the picker (label,
// host, host:port or id) that resolve turns into its id. keysDir holds the
// credentials. It returns the remote command's exit code, 255 for shells'
// own errors (as ssh does), 2 for bad usage.
func Main(args []string, keysDir string, resolve func(name string) (string, error)) int {
	sigs := make(chan os.Signal, 1)
	var code int
	var err error
	switch {
	case args[0] == "exec" && len(args) >= 3:
		cmd := args[2:]
		if cmd[0] == "--" {
			cmd = cmd[1:]
		}
		if len(cmd) == 0 {
			break
		}
		var id string
		if id, err = resolve(args[1]); err == nil {
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
			code, err = Run(keysDir, id, strings.Join(cmd, " "), os.Stdin, os.Stdout, sigs)
		}
		return exit(code, err)
	case args[0] == "connect" && (len(args) == 2 || len(args) == 3 || len(args) == 4):
		// connect <name>: a terminal of its own. connect <id> <sid>
		// [marker]: the PTY of a local session (ssh.Spawn opened sid).
		id, sid, marker := args[1], "", ""
		if len(args) == 2 {
			id, err = resolve(args[1])
		} else {
			sid = args[2]
			if len(args) == 4 {
				marker = args[3]
			}
		}
		if err == nil {
			signal.Notify(sigs, syscall.SIGWINCH, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
			code, err = connectTTY(keysDir, id, sid, marker, sigs)
		}
		return exit(code, err)
	}
	fmt.Fprintln(os.Stderr, usage)
	return 2
}

func exit(code int, err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, "shells:", err)
		return 255
	}
	return code
}

// remote is ssh-keys/<id>.shells: what it takes to reach and authenticate
// one remote. Never the plain secret.
type remote struct {
	URL         string `json:"url"`              // https://host[:port], origin only
	Salt        string `json:"salt"`             // hex, as the remote's crypto-ack sends it
	SecretHash  string `json:"secretHash"`       // hex PBKDF2(secret, salt)
	Fingerprint string `json:"fingerprint"`      // the remote's identity key, pinned at setup
	TLSPin      string `json:"tlsPin,omitempty"` // hex SHA-256 of a self-signed leaf; empty: system roots
	GUC         string `json:"guc,omitempty"`    // socket.cat relay session, sent as the GUC cookie (device pairing, guc G1–G3)
}

// credPath: the id is a connection UUID and names a file in keysDir, so
// UUID characters only (no '/', no '.').
func credPath(keysDir, id string) (string, error) {
	if len(id) != 36 || !util.OnlyChars(id, "0123456789abcdefABCDEF-") {
		return "", fmt.Errorf("invalid connection id %q", id)
	}
	return filepath.Join(keysDir, id+".shells"), nil
}

func load(keysDir, id string) (*remote, error) {
	p, err := credPath(keysDir, id)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("no stored secret for this connection: add it again in the picker")
	}
	if err != nil {
		return nil, err
	}
	var r remote
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if origin, _, _, err := NormalizeURL(r.URL); err != nil || origin != r.URL {
		return nil, fmt.Errorf("%s: bad url", p)
	}
	if h, err := hex.DecodeString(r.SecretHash); err != nil || len(h) != 32 || r.Fingerprint == "" || r.Salt == "" {
		return nil, fmt.Errorf("%s: incomplete", p)
	}
	return &r, nil
}

func save(keysDir, id string, r *remote) error {
	p, err := credPath(keysDir, id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	return fsutil.AtomicWrite(p, append(out, '\n')) // 0600
}

// NormalizeURL keeps the origin of an https URL: no user info, path, query
// or fragment; the host validated like an SSH host. It returns the origin,
// the bare hostname (TLS server name) and the port (443 by default).
func NormalizeURL(raw string) (origin, host string, port int, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return "", "", 0, errors.New("the remote must be an https:// URL without user info")
	}
	host = strings.ToLower(u.Hostname())
	if !util.ValidHostname(host) {
		return "", "", 0, fmt.Errorf("invalid host %q", u.Hostname())
	}
	origin, port = "https://"+host, 443
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return "", "", 0, fmt.Errorf("invalid port %q", p)
		}
		if port != 443 {
			origin += ":" + p
		}
	}
	return origin, host, port, nil
}

// tlsConfig checks the remote's certificate against the system roots, or,
// when pin is set, by the SHA-256 of its (self-signed) leaf alone. With learn
// set (setup), a leaf the system roots reject is let through and its pin
// stored in *learn: trust on first use, like StrictHostKeyChecking=accept-new.
func tlsConfig(host, pin string, learn *string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no TLS certificate")
			}
			leaf := cs.PeerCertificates[0]
			sum := sha256.Sum256(leaf.Raw)
			got := hex.EncodeToString(sum[:])
			if pin != "" {
				if got != pin {
					return fmt.Errorf("TLS certificate changed (SHA-256 %s, pinned %s): refusing; if expected, remove the connection and add it again", got, pin)
				}
				return nil
			}
			opts := x509.VerifyOptions{DNSName: host, Intermediates: x509.NewCertPool()}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			_, err := leaf.Verify(opts)
			if err != nil && learn != nil {
				*learn = got
				return nil
			}
			return err
		},
	}
}
