// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package session manages PTY-backed terminal sessions: creation, destruction,
// output buffering (ring buffer), VT stream parsing (mode/title tracking), and
// session lifecycle events.
package session

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shells/internal/config"
	"shells/internal/pty"
	"shells/internal/ringbuf"
	"shells/internal/stream"
	"shells/internal/util"
)

// Backend describes how a session's process should be launched.
type Backend struct {
	Type         string // "" (local), "ssh"
	ConnectionID string
	Host         string
	User         string
	Port         int
	Hostname     string
}

// ErrCwdUnusable is returned by Create when an explicitly requested working
// directory cannot be used. It lets the API layer surface a clear error to the
// client instead of silently opening a shell in the default directory.
var ErrCwdUnusable = errors.New("cwd not usable")

// ErrCommandNotFound is returned by Create when an explicitly requested bare
// command has no matching binary on PATH, so a missing program (e.g. "opencode")
// fails loudly instead of spawning a shell that immediately exits with
// "command not found".
var ErrCommandNotFound = errors.New("command not found")

// maxCarry bounds the carry buffer when the PTY emits an unterminated escape
// sequence (e.g. ESC ] followed by binary with no BEL/ST): the parser stays
// mid-OSC, safe stays 0, and every byte would otherwise be appended to carry
// and held out of the ring indefinitely. Matches the stream parser's own
// oscText cap.
const maxCarry = 4096

// Session represents one live terminal.
type Session struct {
	ID           string
	Pid          int
	Cols         int
	Rows         int
	Cwd          string
	Term         *pty.Term
	Title        string
	DefaultTitle string
	IsRemote     bool
	CreatedAt    int64
	Clients      int

	mu           sync.Mutex
	outputBuffer *ringbuf.Buffer
	activeModes  map[string]bool
	streamParser *stream.Parser
	destroyed    bool
	// carry holds the trailing bytes of a partially-received escape sequence
	// (parser not back in the ground state). It is prepended to the next
	// chunk before pushing to outputBuffer so replayed chunks never start
	// mid-sequence. Only touched from the session's OnData goroutine.
	carry []byte

	// Set by wshandler to identify the active (foreground) client for this
	// session — the one whose dimensions are applied to the PTY. Compared by
	// identity (==) like the JS ws === session.activeWs check.
	ActiveWS any
}

// Manager owns the session registry and lifecycle events.
type Manager struct {
	cfg *config.Config

	mu       sync.Mutex
	sessions map[string]*Session

	onCreate  func(*Session)
	onDestroy func(string)

	// SpawnSSH, if set, launches an SSH-backed terminal. Set by the ssh
	// package after registration to avoid an import cycle.
	SpawnSSH func(backend *Backend, cols, rows int, command, cwd string) (*pty.Term, string, string, error)
}

// New creates a Manager bound to the given configuration.
func New(cfg *config.Config) (*Manager, error) {
	return &Manager{
		cfg:      cfg,
		sessions: make(map[string]*Session),
	}, nil
}

// OnCreate registers a callback fired after a session is created.
func (m *Manager) OnCreate(fn func(*Session)) { m.onCreate = fn }

// OnDestroy registers a callback fired after a session is destroyed.
func (m *Manager) OnDestroy(fn func(string)) { m.onDestroy = fn }

// Get returns the session with the given ID, or nil.
func (m *Manager) Get(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

// All returns a snapshot of all live sessions.
func (m *Manager) All() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// Count returns the number of live sessions.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// Create spawns a new session. cols/rows default to 80×24. command (if
// non-empty) runs as `shell -c command`. cwd overrides the working directory
// when allowed. backend selects SSH when non-nil.
func (m *Manager) Create(cols, rows int, command, cwd string, backend *Backend) (*Session, error) {
	if m.Count() >= m.cfg.MaxSessions {
		return nil, fmt.Errorf("max sessions (%d) reached", m.cfg.MaxSessions)
	}

	id := util.NewUUID()

	var term *pty.Term
	var workingDir string
	var title string
	var isRemote bool

	if backend != nil && backend.Type == "ssh" {
		if m.SpawnSSH == nil {
			return nil, fmt.Errorf("SSH backend not available")
		}
		if backend.Host == "" || backend.User == "" {
			return nil, fmt.Errorf("SSH backend requires host and user")
		}
		t, dir, ttl, err := m.SpawnSSH(backend, cols, rows, command, cwd)
		if err != nil {
			return nil, err
		}
		term = t
		// SpawnSSH returns the actual cwd when known; for SSH it is unknown
		// (remote), so fall back to the requested cwd — the folder the user
		// picked — so the session exposes a meaningful Cwd (badge, restore).
		if dir != "" {
			workingDir = dir
		} else {
			workingDir = cwd
		}
		title = ttl
		isRemote = true
	} else if backend != nil && backend.Type != "" {
		return nil, fmt.Errorf("unknown backend type: %s", backend.Type)
	} else {
		shell := m.cfg.DefaultShell
		var args []string
		if command != "" {
			args = []string{"-c", command}
		}

		workingDir = m.cfg.Cwd
		if cwd != "" {
			info, statErr := os.Stat(cwd)
			if statErr != nil {
				return nil, fmt.Errorf("%w: %q: %v", ErrCwdUnusable, cwd, statErr)
			}
			if !info.IsDir() {
				return nil, fmt.Errorf("%w: %q: not a directory", ErrCwdUnusable, cwd)
			}
			// EvalSymlinks is only normalization: a stat-valid cwd is never
			// discarded, even if symlink resolution fails (e.g. FUSE mounts).
			workingDir = cwd
			if real, err := filepath.EvalSymlinks(cwd); err == nil {
				workingDir = real
			} else {
				log.Printf("session: EvalSymlinks(%q): %v — using requested path", cwd, err)
			}
		}

		// Bare commands are checked against PATH so a missing binary fails
		// loudly. Compound commands (with spaces) and path-qualified commands
		// are left to the shell.
		if command != "" && !strings.ContainsAny(command, " \t/") {
			if _, err := exec.LookPath(command); err != nil {
				return nil, fmt.Errorf("%w: %q", ErrCommandNotFound, command)
			}
		}

		cols = util.ClampInt(cols, 80, 1, 500)
		rows = util.ClampInt(rows, 24, 1, 200)
		env := buildShellEnv(m.cfg, shell, workingDir)
		t, err := pty.Spawn(shell, args, env, workingDir, cols, rows)
		if err != nil {
			return nil, err
		}
		term = t

		if command != "" {
			title = filepath.Base(workingDir) + " > " + command
		} else {
			title = "shell #" + id[:8]
		}
	}

	s := &Session{
		ID:           id,
		Pid:          term.Pid(),
		Cols:         cols,
		Rows:         rows,
		Cwd:          workingDir,
		Term:         term,
		Title:        title,
		DefaultTitle: "shell #" + id[:8],
		IsRemote:     isRemote,
		CreatedAt:    time.Now().UnixMilli(),
		outputBuffer: ringbuf.New(m.cfg.OutputBufferMax),
		activeModes:  make(map[string]bool),
	}
	s.streamParser = stream.New(
		func(mode string, isSet bool) {
			s.mu.Lock()
			if isSet {
				s.activeModes[mode] = true
			} else {
				delete(s.activeModes, mode)
			}
			s.mu.Unlock()
		},
		func(title string) {
			s.mu.Lock()
			s.Title = title
			s.mu.Unlock()
		},
	)

	// Feed PTY output into the ring buffer + stream parser.
	term.OnData(func(data []byte) {
		if s.IsDestroyed() {
			return
		}
		// Parse first without holding s.mu, since the stream parser
		// callbacks (setMode, setTitle) also acquire s.mu.
		safe := s.streamParser.Parse(data)
		if safe == 0 {
			// The whole chunk is a continuation of a partial escape
			// sequence: accumulate it in carry and push nothing, since an
			// incomplete sequence must never reach the ring.
			if len(data) > 0 {
				if len(s.carry) >= maxCarry {
					// Pathological-case bound: an unterminated sequence
					// (e.g. ESC ] + binary, no BEL/ST) would otherwise grow
					// carry forever. Flush the accumulated bytes as a
					// best-effort chunk — it may start mid-sequence, but
					// that is preferable to unbounded memory. The ring
					// retains the slice by reference, so push a copy
					// before carry's backing array is reused.
					flush := make([]byte, len(s.carry))
					copy(flush, s.carry)
					s.carry = s.carry[:0]
					s.mu.Lock()
					s.outputBuffer.Push(flush, len(flush))
					s.mu.Unlock()
				}
				s.carry = append(s.carry, data...)
			}
			return
		}
		// Only push bytes that end on a clean boundary, re-attaching any
		// trailing partial escape sequence from the previous chunk so a
		// replayed ring never starts mid-sequence.
		var toPush []byte
		if len(s.carry) > 0 {
			toPush = make([]byte, 0, len(s.carry)+safe)
			toPush = append(toPush, s.carry...)
			toPush = append(toPush, data[:safe]...)
		} else {
			toPush = data[:safe]
		}
		s.carry = append(s.carry[:0], data[safe:]...)
		if len(toPush) > 0 {
			s.mu.Lock()
			s.outputBuffer.Push(toPush, len(toPush))
			s.mu.Unlock()
		}
	})

	// Auto-destroy on process exit.
	term.OnExit(func(code int, signal string) {
		if s.IsDestroyed() {
			return
		}
		m.destroy(s)
	})

	m.mu.Lock()
	// Re-check: another Create may have filled the gap while we spawned.
	if len(m.sessions) >= m.cfg.MaxSessions {
		m.mu.Unlock()
		_ = s.Term.Kill() // orphaned PTY — clean up
		return nil, fmt.Errorf("max sessions (%d) reached", m.cfg.MaxSessions)
	}
	m.sessions[id] = s
	m.mu.Unlock()

	if m.onCreate != nil {
		m.onCreate(s)
	}

	return s, nil
}

// Destroy kills and removes the session with the given ID.
func (m *Manager) Destroy(id string) bool {
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return false
	}
	return m.destroy(s)
}

func (m *Manager) destroy(s *Session) bool {
	s.mu.Lock()
	if s.destroyed {
		s.mu.Unlock()
		return false
	}
	s.destroyed = true
	s.mu.Unlock()

	_ = s.Term.Kill()

	m.mu.Lock()
	delete(m.sessions, s.ID)
	m.mu.Unlock()

	if m.onDestroy != nil {
		m.onDestroy(s.ID)
	}
	return true
}

// DestroyAll kills every live session (used during graceful shutdown).
func (m *Manager) DestroyAll() {
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.sessions = make(map[string]*Session)
	m.mu.Unlock()
	for _, s := range all {
		s.mu.Lock()
		s.destroyed = true
		s.mu.Unlock()
		_ = s.Term.Kill()
		if m.onDestroy != nil {
			m.onDestroy(s.ID)
		}
	}
}

// --- Session accessors (thread-safe) ---

func (s *Session) IsDestroyed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.destroyed
}

func (s *Session) GetTitle() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Title
}

func (s *Session) SetTitle(title string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Title = title
}

// GetRestorableDecModes returns active DEC modes that are safe to replay to a
// late-joining client (excludes screen-switching modes like 1049).
func (s *Session) GetRestorableDecModes(cfg *config.Config) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var modes []string
	for mode, isSet := range s.activeModes {
		if isSet && !cfg.NonReplayableDecModes[mode] {
			modes = append(modes, mode)
		}
	}
	return modes
}

// InAlternateScreen reports whether the session's terminal is currently in the
// alternate screen buffer (DEC mode 1049).
func (s *Session) InAlternateScreen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeModes["1049"]
}

// OutputSnapshot returns a copy of all buffered output chunks for replay.
func (s *Session) OutputSnapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outputBuffer.Snapshot()
}

// OutputBufferLen returns the number of chunks in the output buffer.
func (s *Session) OutputBufferLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outputBuffer.Len()
}

// AddClient increments and returns the client count.
func (s *Session) AddClient() int {
	s.mu.Lock()
	s.Clients++
	n := s.Clients
	s.mu.Unlock()
	return n
}

// RemoveClient decrements and returns the client count (floored at 0).
func (s *Session) RemoveClient() int {
	s.mu.Lock()
	s.Clients--
	if s.Clients < 0 {
		s.Clients = 0
	}
	n := s.Clients
	s.mu.Unlock()
	return n
}

// ClientCount returns the current number of attached clients.
func (s *Session) ClientCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Clients
}

// GetActiveWS returns the active (foreground) client identity.
func (s *Session) GetActiveWS() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ActiveWS
}

// SetActiveWS sets the active (foreground) client identity.
func (s *Session) SetActiveWS(ws any) {
	s.mu.Lock()
	s.ActiveWS = ws
	s.mu.Unlock()
}

// SetSize updates the PTY dimensions cached on the session.
func (s *Session) SetSize(cols, rows int) {
	s.mu.Lock()
	s.Cols = cols
	s.Rows = rows
	s.mu.Unlock()
}

// GetSize returns the cached PTY dimensions.
func (s *Session) GetSize() (int, int) {
	s.mu.Lock()
	cols, rows := s.Cols, s.Rows
	s.mu.Unlock()
	return cols, rows
}

// --- helpers ---

func buildShellEnv(cfg *config.Config, shell, workingDir string) []string {
	env := []string{
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
	}
	for _, key := range cfg.ShellEnvKeys {
		if key == "SHELL" && shell != "" {
			env = append(env, "SHELL="+shell)
		} else if val := os.Getenv(key); val != "" {
			env = append(env, key+"="+val)
		}
	}
	env = append(env, "PWD="+workingDir)
	return env
}
