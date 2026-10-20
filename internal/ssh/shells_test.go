// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package ssh_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"shells/internal/config"
	"shells/internal/federate"
	"shells/internal/federate/fedtest"
	"shells/internal/session"
	"shells/internal/ssh"
)

// TestMain lets this test binary stand in for shells in spawnShells' PTY:
// os.Executable() runs it as `connect <id> <sid> [marker]`.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "connect" {
		_, keys := config.SSHPaths(config.KeyDir())
		os.Exit(federate.Main(os.Args[1:], keys, nil))
	}
	os.Exit(m.Run())
}

type output struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (o *output) add(p []byte) { o.mu.Lock(); o.buf.Write(p); o.mu.Unlock() }

func (o *output) has(s string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return strings.Contains(o.buf.String(), s)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestShellsRemote walks a shells remote through the SSH model: setup like
// ssh-setup (label from the remote's hostname), the CLI's name resolution,
// and Spawn: typed errors from the remote, an interactive PTY that reaches
// it, the remote session deleted when the PTY is killed, a command's exit
// code.
func TestShellsRemote(t *testing.T) {
	rm := fedtest.Start(t)
	dir := t.TempDir()
	t.Setenv("SHELLS_KEY_DIR", dir) // what spawnShells hands the PTY child
	cfg := &config.Config{ServerKeyDir: dir}
	cfg.SSHConnectionsFile, cfg.SSHKeysDir = config.SSHPaths(dir)
	m := ssh.NewManager(cfg)

	conn, err := m.SetupShells(rm.URL, []byte(fedtest.Secret))
	if err != nil {
		t.Fatal(err)
	}
	host, _ := exec.Command("hostname", "-s").Output()
	if conn.Kind != "shells" || conn.User != "" || conn.Hostname != strings.TrimSpace(string(host)) {
		t.Fatalf("connection = %+v", conn)
	}
	if again, err := m.SetupShells(rm.URL+"/x", []byte(fedtest.Secret)); err != nil || again.ID != conn.ID || len(m.All()) != 1 {
		t.Fatalf("second setup = %+v, %v; want the same entry", again, err)
	}
	for _, name := range []string{conn.Hostname, conn.ID, fmt.Sprintf("%s:%d", conn.Host, conn.Port), rm.URL} {
		if got, err := ssh.ResolveShells(cfg.SSHConnectionsFile, name); err != nil || got != conn.ID {
			t.Errorf("ResolveShells(%q) = %q, %v", name, got, err)
		}
	}

	spawn := ssh.Spawn(cfg)
	b := &session.Backend{Type: "ssh", Kind: "shells", ConnectionID: conn.ID, Host: conn.Host, Port: conn.Port, Hostname: conn.Hostname}
	if _, _, _, err := spawn(b, 80, 24, "", rm.Dir+"/nope"); !errors.Is(err, session.ErrCwdUnusable) {
		t.Fatalf("spawn in a missing remote cwd: %v", err)
	}
	if _, _, _, err := spawn(b, 80, 24, "no-such-command-x", ""); !errors.Is(err, session.ErrCommandNotFound) {
		t.Fatalf("spawn of a missing remote command: %v", err)
	}
	if term, _, _, err := spawn(b, 80, 24, "true", ""); err != nil {
		t.Fatalf("spawn of a bare remote command: %v", err)
	} else {
		_ = term.Kill()
	}

	term, _, title, err := spawn(b, 80, 24, "", rm.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if title != "shells: "+conn.Hostname {
		t.Errorf("title = %q", title)
	}
	var out output
	term.OnData(out.add)
	waitFor(t, "the remote session", func() bool { return rm.Mgr.Count() == 1 })
	_, _ = term.Write([]byte("echo fed-$((40+2))\r"))
	waitFor(t, "remote output", func() bool { return out.has("fed-42") })
	_ = term.Kill() // what closing the tab does
	waitFor(t, "the remote session to be deleted", func() bool { return rm.Mgr.Count() == 0 })

	term, _, _, err = spawn(b, 80, 24, "echo cmd-$((1+1)); exit 4", "")
	if err != nil {
		t.Fatal(err)
	}
	var out2 output
	term.OnData(out2.add)
	code := make(chan int, 1)
	term.OnExit(func(c int, _ string) { code <- c })
	select {
	case c := <-code:
		if c != 4 || !out2.has("cmd-2") {
			t.Errorf("command session: exit %d, output %q", c, out2.buf.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("command session did not exit")
	}
	waitFor(t, "no remote sessions", func() bool { return rm.Mgr.Count() == 0 })
}
