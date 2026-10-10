// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"shells/internal/session"
)

// TestValidateRemoteE2E runs the real ValidateRemote round-trip against a live
// sshd (host 0.0.0.0). Skipped unless SHELLS_E2E=1. Requires the test key to be
// in the local user's authorized_keys; run with e.g.:
//
//	SHELLS_E2E=1 SHELLS_E2E_HOST=127.0.0.1 SHELLS_E2E_USER=x \
//	SHELLS_E2E_KEYDIR=/tmp/shells-e2e-keydir go test ./internal/ssh/ -run E2E
//
// and append the printed pubkey to ~/.ssh/authorized_keys.
func TestValidateRemoteE2E(t *testing.T) {
	if os.Getenv("SHELLS_E2E") != "1" {
		t.Skip("set SHELLS_E2E=1 to run live SSH e2e")
	}
	host := getenv("SHELLS_E2E_HOST", "127.0.0.1")
	user := getenv("SHELLS_E2E_USER", "x")
	keyDir := getenv("SHELLS_E2E_KEYDIR", "/tmp/shells-e2e-keydir")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	connID := getenv("SHELLS_E2E_CONNID", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	keyPath := keyDir + "/" + connID
	if _, err := os.Stat(keyPath); err != nil {
		if err := GenerateKeyPair(keyDir, connID); err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	// Ensure the key is in authorized_keys (idempotent append).
	if b, err := os.ReadFile(os.Getenv("HOME") + "/.ssh/authorized_keys"); err == nil {
		if !strings.Contains(string(b), strings.TrimSpace(string(pub))) {
			t.Fatalf("pubkey not in authorized_keys; append:\n%s", pub)
		}
	} else {
		t.Skip("no authorized_keys to check")
	}

	m := NewManager(testConfig(keyDir))

	if res, err := m.ValidateRemote(connID, host, user, 22, "/tmp", "echo e2e-ok"); res != session.ValidateOK {
		t.Fatalf("valid cwd/cmd: expected session.ValidateOK, got %v (%v)", res, err)
	}
	if res, err := m.ValidateRemote(connID, host, user, 22, "/nonexistent-shells-e2e-xyz", ""); res != session.ValidateCwdBad {
		t.Fatalf("bad cwd: expected session.ValidateCwdBad, got %v (%v)", res, err)
	}
	if res, err := m.ValidateRemote(connID, host, user, 22, "/tmp", "definitely-not-a-binary-shells-e2e-xyz"); res != session.ValidateCmdBad {
		t.Fatalf("bad command: expected session.ValidateCmdBad, got %v (%v)", res, err)
	}
	t.Log("ValidateRemote E2E: OK/CWD-BAD/CMD-BAD all correct")
}

// TestValidateRemoteConnError: ssh unreachable (closed port) must surface as
// session.ValidateConnError, never cwdBad/cmdBad — a connect failure must not block a
// spawn. Hermetic: no live sshd needed, connection is refused immediately.
func TestValidateRemoteConnError(t *testing.T) {
	if !hasSSH() {
		t.Skip("ssh binary not present")
	}
	keyDir := t.TempDir()
	m := NewManager(testConfig(keyDir))
	res, err := m.ValidateRemote(
		"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "127.0.0.1", "root", 1,
		"/tmp", "definitely-not-a-binary-xyz",
	)
	if res != session.ValidateConnError {
		t.Fatalf("expected session.ValidateConnError, got %v", res)
	}
	if err == nil {
		t.Fatal("expected a non-nil error for an unreachable host")
	}
}

// TestValidateRemoteInvalidConnID: ValidateConnectionID rejects before any ssh.
func TestValidateRemoteInvalidConnID(t *testing.T) {
	m := NewManager(testConfig(t.TempDir()))
	res, err := m.ValidateRemote("not-a-uuid", "127.0.0.1", "root", 22, "/tmp", "")
	if res != session.ValidateConnError {
		t.Fatalf("expected session.ValidateConnError, got %v", res)
	}
	if err == nil {
		t.Fatal("expected a non-nil error for an invalid connection ID")
	}
}

// TestValidateRemoteNothingToValidate: no cwd and no bare command must return
// session.ValidateOK WITHOUT any ssh round-trip (nonsense host would hang/refuse if it
// tried to connect).
func TestValidateRemoteNothingToValidate(t *testing.T) {
	m := NewManager(testConfig(t.TempDir()))
	for _, command := range []string{"", "echo hi && pwd"} {
		res, err := m.ValidateRemote(
			"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "255.255.255.255", "root", 22,
			"", command,
		)
		if res != session.ValidateOK {
			t.Fatalf("command %q: expected session.ValidateOK, got %v", command, res)
		}
		if err != nil {
			t.Fatalf("command %q: expected nil err, got %v", command, err)
		}
	}
}

// TestKeyScripts runs the install/remove scripts with a temp HOME: a normal
// authorized_keys, and a dangling one (Proxmox /etc/pve link without pmxcfs)
// that must fall back to authorized_keys2.
func TestKeyScripts(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest shells-it's"
	run := func(home, script string) string {
		cmd := exec.Command("sh", "-c", remoteCommand(script))
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	for _, dangling := range []bool{false, true} {
		home := t.TempDir()
		ssh := filepath.Join(home, ".ssh")
		want := filepath.Join(ssh, "authorized_keys")
		if dangling {
			_ = os.Mkdir(ssh, 0o700)
			_ = os.Symlink("/nonexistent/priv/authorized_keys", want)
			want += "2"
		}
		run(home, installKeyScript(key))
		if b, _ := os.ReadFile(want); string(b) != key+"\n" {
			t.Fatalf("dangling=%v: %s = %q", dangling, want, b)
		}
		if got := run(home, removeKeyScript(key)); !strings.HasSuffix(got, "0") {
			t.Fatalf("dangling=%v: remaining %q", dangling, got)
		}
		if b, _ := os.ReadFile(want); len(b) != 0 {
			t.Fatalf("dangling=%v: key not removed: %q", dangling, b)
		}
	}
}
