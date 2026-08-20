// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package ssh

import (
	"os"
	"strings"
	"testing"
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

	if res, err := m.ValidateRemote(connID, host, user, 22, "/tmp", "echo e2e-ok"); res != validateOK {
		t.Fatalf("valid cwd/cmd: expected validateOK, got %v (%v)", res, err)
	}
	if res, err := m.ValidateRemote(connID, host, user, 22, "/nonexistent-shells-e2e-xyz", ""); res != validateCwdBad {
		t.Fatalf("bad cwd: expected validateCwdBad, got %v (%v)", res, err)
	}
	if res, err := m.ValidateRemote(connID, host, user, 22, "/tmp", "definitely-not-a-binary-shells-e2e-xyz"); res != validateCmdBad {
		t.Fatalf("bad command: expected validateCmdBad, got %v (%v)", res, err)
	}
	t.Log("ValidateRemote E2E: OK/CWD-BAD/CMD-BAD all correct")
}

// TestValidateRemoteConnError: ssh unreachable (closed port) must surface as
// validateConnError, never cwdBad/cmdBad — a connect failure must not block a
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
	if res != validateConnError {
		t.Fatalf("expected validateConnError, got %v", res)
	}
	if err == nil {
		t.Fatal("expected a non-nil error for an unreachable host")
	}
}

// TestValidateRemoteInvalidConnID: ValidateConnectionID rejects before any ssh.
func TestValidateRemoteInvalidConnID(t *testing.T) {
	m := NewManager(testConfig(t.TempDir()))
	res, err := m.ValidateRemote("not-a-uuid", "127.0.0.1", "root", 22, "/tmp", "")
	if res != validateConnError {
		t.Fatalf("expected validateConnError, got %v", res)
	}
	if err == nil {
		t.Fatal("expected a non-nil error for an invalid connection ID")
	}
}

// TestValidateRemoteNothingToValidate: no cwd and no bare command must return
// validateOK WITHOUT any ssh round-trip (nonsense host would hang/refuse if it
// tried to connect).
func TestValidateRemoteNothingToValidate(t *testing.T) {
	m := NewManager(testConfig(t.TempDir()))
	for _, command := range []string{"", "echo hi && pwd"} {
		res, err := m.ValidateRemote(
			"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "255.255.255.255", "root", 22,
			"", command,
		)
		if res != validateOK {
			t.Fatalf("command %q: expected validateOK, got %v", command, res)
		}
		if err != nil {
			t.Fatalf("command %q: expected nil err, got %v", command, err)
		}
	}
}
