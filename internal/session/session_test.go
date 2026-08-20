// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package session

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
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

	var out strings.Builder
	cancel := s.Term.OnData(func(data []byte) {
		out.Write(data)
	})
	defer cancel()
	if _, err := s.Term.Write([]byte("pwd\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), dir) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(out.String(), dir) {
		t.Fatalf("bash did not land in cwd %q: %q", dir, out.String())
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
