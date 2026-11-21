// SPDX-License-Identifier: AGPL-3.0-or-later
// Shells — socket.cat. Author: Carles Ortega Ragull <ragull@socket.cat>

package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"shells/internal/config"
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

// TestMain doubles as a fake "staged server" for TestPreflightFreePort and
// TestPreflightOverridesShellsPort: when re-executed with PREFLIGHT_HELPER=1
// it only answers /api/health on its resolved port, matching config.Load.
func TestMain(m *testing.M) {
	if os.Getenv("PREFLIGHT_HELPER") == "1" {
		http.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"status":"healthy"}`)) })
		port := os.Getenv("SHELLS_PORT")
		if port == "" {
			port = os.Getenv("PORT")
		}
		_ = http.ListenAndServe(net.JoinHostPort(config.ListenHost(), port), nil)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestPreflightOverridesShellsPort asserts that when the parent process was
// started with SHELLS_PORT set, pre-flight overrides both SHELLS_PORT and PORT
// so the staged child binds the ephemeral testPort instead of colliding with
// the parent listener.
func TestPreflightOverridesShellsPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	parentPort := l.Addr().(*net.TCPAddr).Port
	defer l.Close() // simulate parent occupying its configured SHELLS_PORT

	t.Setenv("SHELLS_PORT", strconv.Itoa(parentPort))
	t.Setenv("PORT", strconv.Itoa(parentPort))
	t.Setenv("PREFLIGHT_HELPER", "1")
	t.Setenv("SHELLS_TLS", "off")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !preflight(self, 0, "") {
		t.Fatal("pre-flight failed when SHELLS_PORT was exported: child collided with parent")
	}
}

// TestPreflightProbesListenHost: the staged child binds SHELLS_HOST, so
// pre-flight must probe that host, not a hard-coded 127.0.0.1 — otherwise any
// non-loopback SHELLS_HOST (or inherited HOST) refuses every update.
func TestPreflightProbesListenHost(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 not bindable here:", err)
	}
	l.Close()
	t.Setenv("SHELLS_HOST", "127.0.0.2")
	t.Setenv("PREFLIGHT_HELPER", "1")
	t.Setenv("SHELLS_TLS", "off")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !preflight(self, 0, "") {
		t.Fatal("pre-flight failed with SHELLS_HOST=127.0.0.2: probed the wrong host")
	}
}

// TestPreflightFreePort: with no TEST_PORT, pre-flight must not depend on a
// fixed port — the old default 8099 collided with an unrelated `php -S` and
// every update was refused.
func TestPreflightFreePort(t *testing.T) {
	if l, err := net.Listen("tcp", ":8099"); err == nil { // occupy it (or it already is)
		defer l.Close()
	}
	t.Setenv("PREFLIGHT_HELPER", "1")
	t.Setenv("SHELLS_TLS", "off")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !preflight(self, 0, "") {
		t.Fatal("pre-flight failed with 8099 taken: it must pick a free port")
	}
}

// TestPreflightRejectsForeignServer: a different server answering 200 on the
// pre-flight port must not pass for the staged binary.
func TestPreflightRejectsForeignServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<html>ok</html>")) }))
	defer l.Close()
	t.Setenv("SHELLS_TLS", "off")
	// /bin/true exits at once: only the foreign server is left answering.
	if preflight("/bin/true", l.Addr().(*net.TCPAddr).Port, "") {
		t.Fatal("pre-flight accepted a foreign server's 200 as the staged binary")
	}
}

// TestWaitOrSignal: a child killed by a signal the supervisor did not
// forward (OOM, kill -9, a stray TERM) is a crash, rc 1, so restart and
// rollback apply; exit codes pass through; a stop signal at the supervisor
// wins.
func TestWaitOrSignal(t *testing.T) {
	for _, c := range []struct {
		cmd string
		rc  int
	}{
		{"exit 0", 0},
		{"exit 5", 5},
		{"kill -KILL $$", 1},
		{"kill -TERM $$", 1},
	} {
		child := exec.Command("sh", "-c", c.cmd)
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		if rc, stop := waitOrSignal(child, make(chan os.Signal, 1)); rc != c.rc || stop {
			t.Errorf("%s: rc=%d stop=%v, want rc=%d stop=false", c.cmd, rc, stop, c.rc)
		}
	}
	sig := make(chan os.Signal, 1)
	sig <- syscall.SIGTERM
	child := exec.Command("sh", "-c", "exit 0")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if _, stop := waitOrSignal(child, sig); !stop {
		t.Error("a stop signal at the supervisor did not stop it")
	}
	// A group stop that kills the child before our handler has queued it:
	// the stop arrives late, within stopGrace, and still counts as a stop.
	late := make(chan os.Signal, 1)
	child = exec.Command("sh", "-c", "kill -TERM $$")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(50*time.Millisecond, func() { late <- syscall.SIGTERM })
	if rc, stop := waitOrSignal(child, late); !stop {
		t.Errorf("a group stop that reached the supervisor late was a crash (rc=%d)", rc)
	}
}

// TestCrashCount: crashes spaced by healthy service never add up to the
// rollback limit; quick ones do.
func TestCrashCount(t *testing.T) {
	n := 0
	for range 3 {
		n = crashCount(n, 2*healthyRun)
	}
	if n != 1 {
		t.Errorf("three crashes after healthy runs counted %d, want 1", n)
	}
	n = 0
	for range 3 {
		n = crashCount(n, time.Second)
	}
	if n != 3 {
		t.Errorf("three quick crashes counted %d, want 3", n)
	}
}

// TestStopSignals: HUP stops the supervisor like TERM, unless the launch
// ignored it (nohup), which then stays ignored.
func TestStopSignals(t *testing.T) {
	has := func() bool {
		for _, s := range stopSignals() {
			if s == syscall.SIGHUP {
				return true
			}
		}
		return false
	}
	if !has() {
		t.Error("SIGHUP is not a stop signal")
	}
	signal.Ignore(syscall.SIGHUP)
	defer func() { // Reset keeps the ignored bit; Notify clears it
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		signal.Stop(c)
	}()
	if has() {
		t.Error("SIGHUP caught although the launch ignored it (nohup)")
	}
}
