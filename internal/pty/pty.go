// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package pty provides a pseudo-terminal abstraction: spawning a process
// inside a Unix98 (Linux, FreeBSD) or BSD (macOS) PTY pair, reading/writing
// data, resizing the window, and subscribing to output/exit events.
//
// It is implemented with the Go standard library only (no CGO). The
// platform-specific PTY allocation lives in openpty_{linux,darwin}.go.
package pty

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

type dataListener struct {
	id uint64
	fn func([]byte)
}

type exitListener struct {
	id uint64
	fn func(exitCode int, signal string)
}

// Term wraps a PTY master fd and the process running inside it.
type Term struct {
	master *os.File
	cmd    *exec.Cmd
	pid    int

	mu            sync.Mutex
	nextID        uint64
	dataListeners []dataListener
	exitListeners []exitListener

	closeOnce sync.Once
}

// Spawn starts name with args inside a new PTY. The initial window size is set
// to cols×rows. env overrides the child environment (nil = inherit). dir sets
// the working directory (empty = inherit).
func Spawn(name string, args, env []string, dir string, cols, rows int) (*Term, error) {
	master, slave, err := openPty()
	if err != nil {
		return nil, err
	}
	if cols > 0 && rows > 0 {
		_ = setWinsize(master.Fd(), cols, rows)
	}

	cmd := exec.Command(name, args...)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0,
	}
	if env != nil {
		cmd.Env = env
	}
	if dir != "" {
		cmd.Dir = dir
	}

	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		return nil, fmt.Errorf("pty: start %s: %w", name, err)
	}

	// Parent does not need the slave end.
	slave.Close()

	t := &Term{master: master, cmd: cmd, pid: cmd.Process.Pid}

	readDone := make(chan struct{})

	go func() {
		defer close(readDone)
		buf := make([]byte, 8192)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				t.dispatchData(chunk)
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		err := cmd.Wait()
		exitCode, signal := extractExit(err)
		t.closeMaster()
		<-readDone // drain remaining output before notifying exit
		t.dispatchExit(exitCode, signal)
	}()

	return t, nil
}

// Pid returns the child process ID.
func (t *Term) Pid() int { return t.pid }

// Write sends data to the PTY master (i.e. to the child's stdin).
func (t *Term) Write(data []byte) (int, error) { return t.master.Write(data) }

// Resize updates the PTY window size.
func (t *Term) Resize(cols, rows int) error {
	return setWinsize(t.master.Fd(), cols, rows)
}

// SignalWinch delivers SIGWINCH to the foreground process group of the PTY and
// forces a full TUI redraw by applying a transient row change: rows are bumped
// by one and then restored to the exact original size, so diff-based full-screen
// TUIs (pi/codex/opencode) detect a real resize and repaint their whole frame.
// (TIOCSIG cannot be used: the Linux kernel only honours SIGINT/SIGQUIT/SIGTSTP
// there.)
func (t *Term) SignalWinch() error {
	var ws winsize
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, t.master.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws))); errno != 0 {
		return errno
	}
	// A diff-based full-screen TUI (pi/codex) only redraws its whole frame on a
	// real size change; an Xpixel-only flip delivers SIGWINCH but leaves
	// rows/cols unchanged and is ignored. Bump the row count and restore it so
	// the foreground process detects a resize and repaints fully.
	ws.Row++
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, t.master.Fd(), uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(&ws))); errno != 0 {
		return errno
	}
	ws.Row--
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, t.master.Fd(), uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return errno
	}
	return nil
}

// Kill sends SIGKILL to the child's entire process group (the child is a
// session leader due to Setsid).
func (t *Term) Kill() error {
	if t.cmd.Process == nil {
		return nil
	}
	_ = syscall.Kill(-t.pid, syscall.SIGKILL)
	return nil
}

// OnData subscribes to PTY output. The returned function unsubscribes.
func (t *Term) OnData(fn func([]byte)) (cancel func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextID++
	id := t.nextID
	t.dataListeners = append(t.dataListeners, dataListener{id, fn})
	return func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		for i, l := range t.dataListeners {
			if l.id == id {
				t.dataListeners = append(t.dataListeners[:i], t.dataListeners[i+1:]...)
				break
			}
		}
	}
}

// OnExit subscribes to process termination. The returned function unsubscribes.
func (t *Term) OnExit(fn func(exitCode int, signal string)) (cancel func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextID++
	id := t.nextID
	t.exitListeners = append(t.exitListeners, exitListener{id, fn})
	return func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		for i, l := range t.exitListeners {
			if l.id == id {
				t.exitListeners = append(t.exitListeners[:i], t.exitListeners[i+1:]...)
				break
			}
		}
	}
}

func (t *Term) dispatchData(data []byte) {
	t.mu.Lock()
	cbs := make([]func([]byte), len(t.dataListeners))
	for i, l := range t.dataListeners {
		cbs[i] = l.fn
	}
	t.mu.Unlock()
	for _, cb := range cbs {
		cb(data)
	}
}

func (t *Term) dispatchExit(code int, signal string) {
	t.mu.Lock()
	cbs := make([]func(int, string), len(t.exitListeners))
	for i, l := range t.exitListeners {
		cbs[i] = l.fn
	}
	t.mu.Unlock()
	for _, cb := range cbs {
		cb(code, signal)
	}
}

func (t *Term) closeMaster() {
	t.closeOnce.Do(func() { t.master.Close() })
}

func setWinsize(fd uintptr, cols, rows int) error {
	ws := &winsize{
		Row: uint16(rows),
		Col: uint16(cols),
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
	if errno != 0 {
		return errno
	}
	return nil
}

// winsize matches the kernel struct winsize (4 × uint16).
type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func extractExit(err error) (exitCode int, signal string) {
	if err == nil {
		return 0, ""
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				return -1, status.Signal().String()
			}
			return status.ExitStatus(), ""
		}
		return exitErr.ExitCode(), ""
	}
	return -1, ""
}
