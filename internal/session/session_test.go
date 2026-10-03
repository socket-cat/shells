// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package session

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"shells/internal/config"
	"shells/internal/pty"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	shell, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash not found: %v", err)
	}
	return &config.Config{
		MaxSessions:     4,
		DefaultShell:    shell,
		Cwd:             "/",
		OutputBufferMax: 65536,
		ShellEnvKeys:    []string{},
	}
}

func TestCreateBadCwdFailsLoud(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "nonexistent")
	_, err = m.Create(80, 24, "bash", missing, nil)
	if !errors.Is(err, ErrCwdUnusable) {
		t.Fatalf("expected ErrCwdUnusable, got %v", err)
	}
	if m.Count() != 0 {
		t.Fatalf("session created despite unusable cwd: count=%d", m.Count())
	}
}

func TestCreateValidCwd(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s, err := m.Create(80, 24, "bash", dir, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if s.Cwd != dir {
		t.Fatalf("cwd=%q want %q", s.Cwd, dir)
	}
	m.Destroy(s.ID)
}

func TestSpawnBashLandsInCwd(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s, err := m.Create(80, 24, "", dir, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer m.Destroy(s.ID)

	var mu sync.Mutex
	var out strings.Builder
	cancel := s.Term.OnData(func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		out.Write(data)
	})
	defer cancel()
	if _, err := s.Term.Write([]byte("pwd\n")); err != nil {
		t.Fatal(err)
	}
	output := func() string {
		mu.Lock()
		defer mu.Unlock()
		return out.String()
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(output(), dir) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(output(), dir) {
		t.Fatalf("bash did not land in cwd %q: %q", dir, output())
	}
}

func TestCreateBareCommandNotFoundFailsLoud(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, err = m.Create(80, 24, "definitely-not-a-binary-xyz", dir, nil)
	if !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("expected ErrCommandNotFound, got %v", err)
	}
	if m.Count() != 0 {
		t.Fatalf("session created despite missing command: count=%d", m.Count())
	}
}

func TestCreateCompoundCommandNotValidated(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Create(80, 24, "echo hi && pwd", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("compound command must not be rejected: %v", err)
	}
	m.Destroy(s.ID)
}

func TestBuildShellEnvPWD(t *testing.T) {
	env := buildShellEnv(testConfig(t), "/bin/bash", "/work/dir")
	for _, e := range env {
		if e == "PWD=/work/dir" {
			return
		}
	}
	t.Fatal("PWD not set to the working directory")
}

func TestTryTermWriteLiveThenDestroyed(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Create(80, 24, "", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.TryTermWrite([]byte("echo ok\n")); err != nil {
		t.Fatalf("live write rejected: %v", err)
	}
	m.Destroy(s.ID)
	if _, err := s.TryTermWrite([]byte("x\n")); !errors.Is(err, errDestroyed) {
		t.Fatalf("write after Destroy: want errDestroyed, got %v", err)
	}
	if err := s.TryTermResize(120, 40); !errors.Is(err, errDestroyed) {
		t.Fatalf("resize after Destroy: want errDestroyed, got %v", err)
	}
}

// TestTryTermWriteRaceWithDestroy hammers the guarded write path while Destroy
// lands concurrently; a torn guard+write (TOCTOU use-after-destroy) shows up
// as a panic or a -race report. Run with go test -race.
func TestTryTermWriteRaceWithDestroy(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Create(80, 24, "", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := []byte("echo race\n")
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = s.TryTermWrite(buf) // must never panic, even post-destroy
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	m.Destroy(s.ID)
	close(stop)
	// Writers normally unwind immediately on SIGKILL; a pathological park on
	// a full PTY input buffer may strand one goroutine by design, so the join
	// is best-effort (see TestDestroyDoesNotWedgeOnBlockedPTYWrite).
	if !waitWGWithTimeout(&wg, 5*time.Second) {
		t.Log("writer goroutine parked post-destroy; tolerated by design")
	}
}

// waitWGWithTimeout reports whether wg finished within max.
func waitWGWithTimeout(wg *sync.WaitGroup, max time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(max):
		return false
	}
}

// TestDestroyDoesNotWedgeOnBlockedPTYWrite proves FINDING 1 is dead: a child
// that never reads stdin (`sleep infinity`) lets the kernel PTY input queue
// fill (default ~4KB), so an in-flight TryTermWrite would block indefinitely.
// Under the pre-rework RLock design destroy could not progress at all — this
// test times out there. Post-rework: the flag is set under a short critical
// section, then Kill + bounded drain. SIGKILL unblocks normal consumers;
// a pathological park leaks one goroutine bounded by flood size; Destroy
// itself is always bounded by termOpDrainWait.
//
// Honest limits: the 150ms soak makes blockage overwhelmingly likely but is
// not proof the write was mid-syscall; the sharp assertion is wall-clock
// "Destroy completes in bounded time regardless".
func TestDestroyDoesNotWedgeOnBlockedPTYWrite(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Create(80, 24, "sleep infinity", t.TempDir(), nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	stop := make(chan struct{})
	writersDone := make(chan struct{})
	go func() {
		defer close(writersDone)
		buf := bytes.Repeat([]byte("x"), 4096)
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = s.TryTermWrite(buf)
			}
		}
	}()

	time.Sleep(150 * time.Millisecond) // saturate the PTY input queue
	start := time.Now()
	if !m.Destroy(s.ID) {
		close(stop)
		t.Fatal("destroy reported already-destroyed")
	}
	elapsed := time.Since(start)

	close(stop)
	select {
	case <-writersDone:
	case <-time.After(5 * time.Second):
		// Non-fatal by design: a write parked mid-syscall strands its
		// goroutine until process death; destroy itself stayed bounded.
		t.Log("writer goroutine parked post-destroy; tolerated by design")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("destroy wedged behind blocked writes for %v", elapsed)
	}
}

// sshTestManager returns a Manager wired with a fake SpawnSSH (returns
// "fake spawn reached") and the given SSHValidate result. It proves whether
// validation blocks before spawn: a blocked create returns the typed error,
// a passing create returns the fake spawn error.
func sshTestManager(t *testing.T, res ValidateResult) *Manager {
	t.Helper()
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	m.SSHValidate = func(backend *Backend, command, cwd string) (ValidateResult, error) {
		return res, nil
	}
	m.SpawnSSH = func(backend *Backend, cols, rows int, command, cwd string) (*pty.Term, string, string, error) {
		return nil, "", "", errors.New("fake spawn reached")
	}
	return m
}

func sshBackend() *Backend {
	return &Backend{
		Type:         "ssh",
		ConnectionID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		Host:         "h",
		User:         "u",
		Port:         22,
	}
}

func TestCreateSSHCwdBadFailsLoud(t *testing.T) {
	m := sshTestManager(t, ValidateCwdBad)
	_, err := m.Create(80, 24, "", "/nonexistent-xyz", sshBackend())
	if !errors.Is(err, ErrCwdUnusable) {
		t.Fatalf("expected ErrCwdUnusable, got %v", err)
	}
	if m.Count() != 0 {
		t.Fatalf("session created despite unusable remote cwd: count=%d", m.Count())
	}
}

func TestCreateSSHCmdBadFailsLoud(t *testing.T) {
	m := sshTestManager(t, ValidateCmdBad)
	_, err := m.Create(80, 24, "definitely-not-a-binary-xyz", "", sshBackend())
	if !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("expected ErrCommandNotFound, got %v", err)
	}
	if m.Count() != 0 {
		t.Fatalf("session created despite missing remote command: count=%d", m.Count())
	}
}

func TestCreateSSHOKProceeds(t *testing.T) {
	m := sshTestManager(t, ValidateOK)
	_, err := m.Create(80, 24, "", "/tmp", sshBackend())
	if err == nil || err.Error() != "fake spawn reached" {
		t.Fatalf("expected spawn to be reached, got %v", err)
	}
}

func TestCreateSSHConnErrorProceeds(t *testing.T) {
	m := sshTestManager(t, ValidateConnError)
	_, err := m.Create(80, 24, "", "/tmp", sshBackend())
	if err == nil || err.Error() != "fake spawn reached" {
		t.Fatalf("expected spawn to be reached despite connError, got %v", err)
	}
}

func TestCreateSSHValidateReached(t *testing.T) {
	m := sshTestManager(t, ValidateOK)
	_, err := m.Create(80, 24, "", "", sshBackend())
	if err == nil || err.Error() != "fake spawn reached" {
		t.Fatalf("expected spawn to be reached, got %v", err)
	}
}

// TestDestroyAllWaitsForChildExit proves L-6: after DestroyAll returns, the
// SIGKILLed PTY children are not just signalled but actually reaped —
// kill(pid, 0) reports ESRCH immediately, with no polling grace. `exec`
// replaces the shell image in-place so the session PID is the sleeper itself
// and SIGKILL leaves zero orphans behind.
//
// Honest limits: reap-before-return is deterministic (the exited channel is
// closed strictly after cmd.Wait), but DestroyAll returning early "by luck"
// on an idle machine could also pass a one-shot check; the wall-clock bound
// additionally pins that the global deadline is honored.
func TestDestroyAllWaitsForChildExit(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	const n = 3
	pids := make([]int, n)
	for i := 0; i < n; i++ {
		s, err := m.Create(80, 24, "exec sleep 30", dir, nil)
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		pids[i] = s.Pid
	}

	var destroyed atomic.Int32
	m.OnDestroy(func(string) { destroyed.Add(1) })

	start := time.Now()
	m.DestroyAll()
	elapsed := time.Since(start)

	if elapsed > destroyAllGrace+termOpDrainWait+time.Second {
		t.Fatalf("DestroyAll took %v; global deadline breached", elapsed)
	}
	for i, pid := range pids {
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("child %d (pid %d) still alive right after DestroyAll: %v", i, pid, err)
		}
	}
	if got := destroyed.Load(); got != n {
		t.Fatalf("onDestroy fired %d times, want %d", got, n)
	}
}

func TestDestroyAllSkipsSessionAlreadyBeingDestroyed(t *testing.T) {
	m, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Create(80, 24, "exec sleep 30", t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var destroyed atomic.Int32
	m.OnDestroy(func(string) { destroyed.Add(1) })

	// An in-flight op parks destroy() in its drain wait while the session
	// is still registered, so DestroyAll sees it mid-destroy.
	s.beginTermOp()
	done := make(chan struct{})
	go func() { m.Destroy(s.ID); close(done) }()
	for !s.IsDestroyed() {
		time.Sleep(time.Millisecond)
	}
	m.DestroyAll()
	s.endTermOp()
	<-done

	if got := destroyed.Load(); got != 1 {
		t.Fatalf("onDestroy fired %d times, want 1", got)
	}
}

func TestBuildShellEnvTERM(t *testing.T) {
	t.Setenv("TERM", "dumb")
	t.Setenv("COLORTERM", "none")
	cfg := &config.Config{
		ShellEnvKeys: []string{"HOME", "PATH", "TERM", "COLORTERM"},
	}
	env := buildShellEnv(cfg, "/bin/bash", "/tmp")
	var termVal, colortermVal string
	for _, e := range env {
		if strings.HasPrefix(e, "TERM=") {
			termVal = strings.TrimPrefix(e, "TERM=")
		}
		if strings.HasPrefix(e, "COLORTERM=") {
			colortermVal = strings.TrimPrefix(e, "COLORTERM=")
		}
	}
	if termVal != "xterm-256color" {
		t.Fatalf("expected TERM=xterm-256color, got %s", termVal)
	}
	if colortermVal != "truecolor" {
		t.Fatalf("expected COLORTERM=truecolor, got %s", colortermVal)
	}
}
