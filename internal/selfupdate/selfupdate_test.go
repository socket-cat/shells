// SPDX-License-Identifier: AGPL-3.0-or-later
// Shells — socket.cat. Author: Carles Ortega Ragull <ragull@socket.cat>

package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnabledDefault(t *testing.T) {
	os.Unsetenv("SHELLS_SELFUPDATE_CHILD")
	if !Enabled() {
		t.Fatal("self-update should be on by default")
	}
	os.Setenv("SHELLS_SELFUPDATE_CHILD", "1")
	if Enabled() {
		t.Fatal("the child marker should disable self-update")
	}
	os.Unsetenv("SHELLS_SELFUPDATE_CHILD")
}

func TestChildEnv(t *testing.T) {
	os.Setenv("SHELLS_SELFUPDATE_CHILD", "1")
	os.Setenv("KEEP", "yes")

	got := map[string]string{}
	for _, kv := range childEnv("/tmp/shells") {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			got[kv[:i]] = kv[i+1:]
		}
	}
	if got["KEEP"] != "yes" {
		t.Error("expected unrelated env preserved")
	}
	if got["SHELLS_SELFUPDATE_CHILD"] != "1" {
		t.Error("child marker missing from child env")
	}
	if got["SHELLS_BINARY_PATH"] != "/tmp/shells" {
		t.Errorf("SHELLS_BINARY_PATH = %q, want /tmp/shells", got["SHELLS_BINARY_PATH"])
	}
}

func TestSwapAndRollback(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "shells")
	if err := os.WriteFile(bin, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".new", []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	logf := func(string, ...any) {}

	swap(bin, logf)
	if b, _ := os.ReadFile(bin); string(b) != "new" {
		t.Error("swap did not install the new binary")
	}
	if b, _ := os.ReadFile(bin + ".previous"); string(b) != "old" {
		t.Error("old binary not saved as .previous")
	}

	if err := os.WriteFile(bin, []byte("crashed"), 0o755); err != nil {
		t.Fatal(err)
	}
	rollback(bin, logf)
	if b, _ := os.ReadFile(bin); string(b) != "old" {
		t.Error("rollback did not restore .previous")
	}
}

func TestVerifyStaged(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "shells")
	content := []byte("#!/bin/sh\necho hi\n")
	if err := os.WriteFile(bin+".new", content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if err := os.WriteFile(bin+".new.sha256", []byte(hex.EncodeToString(sum[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	if !verifyStaged(bin) {
		t.Error("should verify a correctly-staged binary")
	}

	if err := os.WriteFile(bin+".new", []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if verifyStaged(bin) {
		t.Error("should reject a tampered staged binary")
	}

	_ = os.Remove(bin + ".new")
	_ = os.Remove(bin + ".new.sha256")
	if verifyStaged(bin) {
		t.Error("should reject a missing sidecar")
	}

	if err := os.WriteFile(bin+".new", content, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".new.sha256", []byte(hex.EncodeToString(sum[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(bin + ".new")
	if err := os.Symlink("/etc/passwd", bin+".new"); err == nil {
		if verifyStaged(bin) {
			t.Error("should reject a symlink staged binary")
		}
	}
}

func TestEnvInt(t *testing.T) {
	os.Setenv("SUP_X", "7")
	if envInt("SUP_X", 3) != 7 {
		t.Error("envInt should read the env value")
	}
	os.Setenv("SUP_X", "junk")
	if envInt("SUP_X", 3) != 3 {
		t.Error("envInt should fall back on non-numeric input")
	}
	os.Unsetenv("SUP_X")
	if envInt("SUP_X", 3) != 3 {
		t.Error("envInt should use the default when unset")
	}
}
