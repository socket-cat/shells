// SPDX-License-Identifier: AGPL-3.0-or-later
// Shells — socket.cat. Author: Carles Ortega Ragull <ragull@socket.cat>

// Package selfupdate makes the binary update itself. The binary runs a child
// copy of itself so a verified self-update can be applied in place — no
// external scripts, works for binary-only deployments.
//
// Flow: the server child stages a verified new binary and exits with code 42;
// the parent pre-flights the staged binary, swaps it in, and restarts,
// rolling back to <binary>.previous after repeated crashes. SIGTERM/SIGINT
// stop cleanly (forward to the child, no restart, no rollback).
//
// The child is marked with the internal SHELLS_SELFUPDATE_CHILD=1 so it never
// spawns its own child (recursion guard).
package selfupdate

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"shells/internal/config"
)

// restartCode is the exit code the server uses to signal "a verified update is
// staged — swap and restart". Matches exitCodeRestart in internal/api.
const restartCode = 42

// PortBusyCode is the exit code the server child reports when it cannot bind
// its port (another instance already holds it). The supervisor treats it as
// "stop cleanly" instead of a crash, so a duplicate launch exits instead of
// crash-looping forever.
const PortBusyCode = 3

// Enabled reports whether the current process should run its own child for
// self-update: true for every process except the child itself (marked with the
// internal SHELLS_SELFUPDATE_CHILD=1).
func Enabled() bool {
	return os.Getenv("SHELLS_SELFUPDATE_CHILD") != "1"
}

// Run manages the server child so the binary can apply its own updates. It
// never returns.
func Run() {
	// Prefer SHELLS_BINARY_PATH (the documented override, also what the child
	// uses) so the parent and child always agree on where updates stage.
	binary := envOr("SHELLS_BINARY_PATH", envOr("BINARY", mustExecutable()))
	// Resolve a symlinked install path so swap() operates on the real file and
	// never replaces the symlink itself.
	if resolved, err := filepath.EvalSymlinks(binary); err == nil {
		binary = resolved
	}
	logPath := os.Getenv("LOG") // empty → child inherits stdio, parent logs to stderr
	crashLimit := envInt("CRASH_LIMIT", 3)
	testPort := envInt("TEST_PORT", 8099)

	logf := makeLogger(logPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	crashes := 0
	startFails := 0
	for {
		child, err := startChild(binary, logPath)
		if err != nil {
			startFails++
			logf("failed to start %s (%d/%d): %v", binary, startFails, crashLimit, err)
			if startFails >= crashLimit && fileExists(binary+".previous") {
				rollback(binary, logf)
				startFails = 0
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		startFails = 0
		logf("started %s (pid %d)", binary, child.Process.Pid)

		rc := waitOrSignal(child, sigCh)
		if rc == -1 { // signal received: stop cleanly — must exit, NOT fall
			// through to the server code below in main().
			logf("stop requested")
			_ = child.Process.Signal(syscall.SIGTERM)
			_, _ = child.Process.Wait()
			os.Exit(0)
		}
		logf("child exited rc=%d", rc)

		switch rc {
		case PortBusyCode:
			// Another instance already owns the port: nothing to restart, and
			// retrying would just burn the loop forever. Exit cleanly.
			logf("port already in use — another instance is running, exiting")
			os.Exit(0)
		case restartCode:
			// Re-verify the staged binary against its sidecar digest before we
			// ever execute or install it (rejects symlinks and tampering).
			if !verifyStaged(binary) {
				logf("staged binary failed verification; keeping current")
				removeStaged(binary)
			} else if preflight(binary+".new", testPort, logPath) {
				swap(binary, logf)
				_ = os.Remove(binary + ".new.sha256")
				crashes = 0
			} else {
				logf("staged binary failed pre-flight; keeping current")
				removeStaged(binary)
			}
		case 0:
			crashes = 0
		default:
			crashes++
			logf("crash %d/%d", crashes, crashLimit)
			if crashes >= crashLimit && fileExists(binary+".previous") {
				rollback(binary, logf)
				crashes = 0
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// startChild launches the server child: same env minus the child marker, with
// SHELLS_BINARY_PATH set so the child stages updates next to the right binary.
func startChild(binary, logPath string) (*exec.Cmd, error) {
	cmd := exec.Command(binary)
	cmd.Env = childEnv(binary)
	if logPath != "" {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			cmd.Stdout = f
			cmd.Stderr = f
		}
	} else {
		// No LOG: inherit the parent's stdio. (Leaving Stdout/Stderr nil
		// would silence the child entirely — nil means /dev/null in os/exec,
		// not inherit — losing startup output like the generated E2E secret.)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if devnull, err := os.Open(os.DevNull); err == nil {
		cmd.Stdin = devnull
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func childEnv(binary string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "SHELLS_SELFUPDATE_CHILD=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "SHELLS_SELFUPDATE_CHILD=1", "SHELLS_BINARY_PATH="+binary)
}

// waitOrSignal returns the child's exit code, or -1 if a TERM/INT signal
// arrived first.
func waitOrSignal(child *exec.Cmd, sigCh chan os.Signal) int {
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-sigCh:
		return -1
	case err := <-done:
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return -1
	}
}

// verifyStaged checks binary.new against its .sha256 sidecar (written by
// release.Apply after verification) and rejects symlinks, so the parent never
// executes or installs anything it did not verify.
func verifyStaged(binary string) bool {
	newBin := binary + ".new"
	fi, err := os.Lstat(newBin)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	wantHex, err := os.ReadFile(newBin + ".sha256")
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(wantHex)))
	if err != nil || len(want) != sha256.Size {
		return false
	}
	f, err := os.Open(newBin)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(h.Sum(nil), want) == 1
}

func removeStaged(binary string) {
	_ = os.Remove(binary + ".new")
	_ = os.Remove(binary + ".new.sha256")
}

// preflight boots the staged binary on testPort and probes /api/health for up
// to ~10s, then stops it. Returns true only if health reports OK.
func preflight(newBin string, testPort int, logPath string) bool {
	if !fileExists(newBin) {
		return false
	}
	cmd := exec.Command(newBin)
	cmd.Env = childEnv(newBin)
	cmd.Env = setEnv(cmd.Env, "PORT", strconv.Itoa(testPort))
	if logPath != "" {
		if f, err := os.OpenFile(logPath+".preflight", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			cmd.Stdout = f
			cmd.Stderr = f
		}
	}
	if devnull, err := os.Open(os.DevNull); err == nil {
		cmd.Stdin = devnull
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	scheme := "http"
	client := &http.Client{Timeout: 2 * time.Second}
	if tlsEnabled() {
		scheme = "https"
		// Loopback-only preflight against the staged binary's self-signed
		// cert, so certificate verification is intentionally skipped.
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	url := fmt.Sprintf("%s://127.0.0.1:%d/api/health", scheme, testPort)
	for i := 0; i < 20; i++ {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func swap(binary string, logf func(string, ...any)) {
	_ = os.Remove(binary + ".previous")
	_ = os.Rename(binary, binary+".previous")
	if err := os.Rename(binary+".new", binary); err != nil {
		logf("swap failed: %v", err)
		return
	}
	_ = os.Chmod(binary, 0o755)
	logf("swapped new binary into place")
}

func rollback(binary string, logf func(string, ...any)) {
	_ = os.Remove(binary + ".broken")
	_ = os.Rename(binary, binary+".broken")
	if err := os.Rename(binary+".previous", binary); err == nil {
		_ = os.Chmod(binary, 0o755)
	}
	logf("rolled back to previous binary")
}

func makeLogger(logPath string) func(string, ...any) {
	return func(format string, args ...any) {
		line := fmt.Sprintf("[selfupdate] %s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
		if logPath != "" {
			if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				_, _ = f.WriteString(line)
				_ = f.Close()
				return
			}
		}
		fmt.Fprint(os.Stderr, line)
	}
}

func setEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return append(out, key+"="+value)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// tlsEnabled reports whether the supervisor's own environment has SHELLS_TLS
// on. It must parse identically to the child's parser (config.EnvTrue), since
// the env is inherited by the staged child: if the preflight probe guessed a
// different scheme than the staged child's listener, every update would fail
// preflight and roll back forever.
func tlsEnabled() bool {
	return config.EnvTrue(os.Getenv("SHELLS_TLS"))
}

func envInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func mustExecutable() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "/tmp/shells"
}
