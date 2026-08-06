// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shells/internal/config"
	"shells/internal/session"
)

// TestE2ERemote runs the full patched SSH path (probe, key gen, binary search,
// spawn with pathBootstrap) against a live host. It is skipped unless
// SHELLS_E2E=1 so normal go vet / go test stays hermetic.
//
// Setup: a key must already be present in authorized_keys on the target, e.g.
//
//	cat /tmp/e2e-keys/<connID>.pub >> ~/.ssh/authorized_keys
func TestE2ERemote(t *testing.T) {
	if os.Getenv("SHELLS_E2E") != "1" {
		t.Skip("set SHELLS_E2E=1 to run live SSH e2e")
	}
	host := getenv("SHELLS_E2E_HOST", "localhost")
	user := getenv("SHELLS_E2E_USER", "x")
	port := 22
	cmd := getenv("SHELLS_E2E_CMD", "echo e2e-ok")
	want := getenv("SHELLS_E2E_MATCH", "e2e-ok")

	keyDir := getenv("SHELLS_E2E_KEYDIR", "/tmp/e2e-keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	connID := getenv("SHELLS_E2E_CONNID", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	// Only generate a key if one doesn't already exist at this path.
	keyPath := filepath.Join(keyDir, connID)
	if _, statErr := os.Stat(keyPath); statErr != nil {
		if genErr := GenerateKeyPair(keyDir, connID); genErr != nil {
			t.Fatalf("GenerateKeyPair: %v", genErr)
		}
		pub, err := os.ReadFile(keyPath + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		pubLine := strings.TrimSpace(string(pub))
		t.Logf("pubkey (install into authorized_keys): %s", pubLine)
		_ = os.WriteFile("/tmp/e2e-pub.txt", []byte(pubLine+"\n"), 0o600)
		t.Log("see /tmp/e2e-pub.txt; append to remote ~/.ssh/authorized_keys")
	}

	cfg := testConfig(keyDir)
	m := NewManager(cfg)

	// Probe
	pr, err := m.Probe(host, user, port)
	if err != nil {
		t.Logf("probe err: %v", err)
	}
	t.Logf("probe: KeyReady=%v HasOurKey=%v Hostname=%q Unreachable=%v",
		pr.KeyReady, pr.HasOurKey, pr.Hostname, pr.Unreachable)

	// SearchRemoteBinaries (compgen / POSIX fallback)
	if bins, err := m.SearchRemoteBinaries(connID, host, user, port, "cli"); err != nil {
		t.Logf("SearchRemoteBinaries err: %v", err)
	} else {
		t.Logf("SearchRemoteBinaries('cli') -> %d: %v", len(bins), bins)
	}

	// Spawn via patched pathBootstrap
	spawn := Spawn(cfg)
	term, title, _, err := spawn(&session.Backend{Type: "ssh", ConnectionID: connID, User: user, Host: host, Port: port}, 80, 24, cmd, "")
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	defer term.Kill()
	t.Log("spawned:", title)

	done := make(chan struct{})
	var buf []byte
	var mu sync.Mutex
	cancel := term.OnData(func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		buf = append(buf, data...)
		if strings.Contains(strings.ToLower(string(buf)), strings.ToLower(want)) {
			close(done)
		}
	})
	defer cancel()

	select {
	case <-done:
		mu.Lock()
		t.Logf("got output: %q", buf)
		mu.Unlock()
	case <-time.After(20 * time.Second):
		mu.Lock()
		t.Fatalf("timeout; output so far: %q", buf)
		mu.Unlock()
	}
}

func testConfig(keyDir string) *config.Config {
	return &config.Config{
		SSHConnectionsFile: filepath.Join(keyDir, "ssh-connections.json"),
		SSHKeysDir:         keyDir,
	}
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func TestRemoteCommandWrapper(t *testing.T) {
	// The outer wrapper must be parseable by ANY login shell (sh, ash, bash,
	// csh, tcsh, zsh): sshd hands it to the login shell, and csh/tcsh single
	// quotes treat everything except ' and ! literally. The wrapper therefore
	// keeps ' and ! only as its own delimiters, never inside the payload —
	// any ' or ! in the payload must be octal-encoded.
	cases := []string{
		`echo "x"`,
		`echo '$HOME'`,
		`echo '!' "bang!"`,
		`cd '/a b/c' 2>/dev/null; export PATH="${PATH:-/usr/local/bin}"; cline --version`,
	}
	for _, payload := range cases {
		out := remoteCommand(payload)
		// Between the two single-quote delimiters the content must contain no
		// literal ' or ! at all (only backslashes + octal digits + the fixed
		// wrapper scaffolding).
		if !strings.HasPrefix(out, `/bin/sh -c '`) || !strings.HasSuffix(out, `")"'`) {
			t.Fatalf("unexpected wrapper shape for %q: %s", payload, out)
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(out, `/bin/sh -c '`), `")"'`)
		if strings.ContainsAny(inner, "'!") {
			t.Fatalf("inner wrapper contains csh-dangerous chars for %q: %s", payload, inner)
		}
	}
	_ = exec.Command
}
