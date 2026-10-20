// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

// exec's remote side is a PTY (the PTY ceiling): stdout and stderr arrive
// merged, stdin is a tty (text piped in is sent, then ^D; binary is
// unsupported). Wide so tools do not cut lines to 80 columns.
const execCols, execRows = 200, 50

// A gate runs before a command and holds it until the client is attached:
// the remote destroys a session the moment its process exits, so a quick
// command would be gone, output and exit status with it, before `attach`
// arrives. The marker, split by an empty quoted string so the command text
// never contains it, says the gate is up; head waits for the line the client
// sends once attached; stty -echo keeps that line off the screen. The
// command goes through eval, so the outer shell parses only the gate: a
// command it cannot parse fails after the gate, error and status intact.
// Plain external commands, ';', eval and single quotes only, so it parses in
// sh, bash, zsh and fish (fish alone reads a backslash inside single quotes
// as an escape).
//
// execGate also keeps echo off (stdin piped in is not echoed back) and drops
// the CR the PTY puts before each LF; connectGate gives the terminal back.
const (
	execGate    = "stty -echo -onlcr; echo shells-gate''-%s; head -n 1 >/dev/null; eval '%s'"
	connectGate = "stty -echo; echo shells-gate''-%s; head -n 1 >/dev/null; stty echo; eval '%s'"
)

func gated(gate, cmd string) (command, marker string) {
	var n [8]byte
	_, _ = rand.Read(n[:])
	nonce := hex.EncodeToString(n[:])
	return fmt.Sprintf(gate, nonce, strings.ReplaceAll(cmd, "'", `'\''`)), "shells-gate-" + nonce
}

// exitIdle is how long the client keeps reading after the exit frame, and
// after each output frame behind it: the remote flushes its last coalesced
// output up to one 8 ms tick after sending exit.
// ponytail: a timing bound (the tick plus scheduling and network jitter, not
// a retransmitted packet); pipe mode sends exit behind all output.
const exitIdle = 25 * time.Millisecond

// goneGrace is how long the client waits for the exit frame after the
// session is gone (the remote sends "gone" first).
const goneGrace = 2 * time.Second

// Run runs cmd on the remote id, like `ssh host cmd`: output to stdout,
// stdin sent then ^D, the remote exit code returned. A signal on sigs deletes
// the remote session and returns 128+n.
func Run(keysDir, id, cmd string, stdin io.Reader, stdout io.Writer, sigs <-chan os.Signal) (int, error) {
	r, err := load(keysDir, id)
	if err != nil {
		return 0, err
	}
	c, err := connect(r)
	if err != nil {
		return 0, err
	}
	defer c.close()
	command, marker := gated(execGate, cmd)
	sid, err := c.open(execCols, execRows, "", command)
	if err != nil {
		return 0, err
	}
	return c.relay(sid, marker, stdin, stdout, sigs, false)
}

// Open creates a remote session for a local one (ssh.Spawn), which then
// attaches its PTY to it with `shells connect <id> <sid> [marker]`. The
// remote checks cwd and command itself: an *APIError with Code cwd_unusable
// or command_not_found.
func Open(keysDir, id string, cols, rows int, cwd, command string) (sid, marker string, err error) {
	r, err := load(keysDir, id)
	if err != nil {
		return "", "", err
	}
	c, err := connect(r)
	if err != nil {
		return "", "", err
	}
	defer c.close()
	if command != "" && !strings.ContainsAny(command, " \t/") {
		// The remote checks a bare command only when it is the whole
		// command, which a gated one never is: ask its command index
		// (compgen -c), as ssh's ValidateRemote runs command -v.
		res, err := c.call("/api/which", map[string]any{"q": command})
		if err != nil {
			return "", "", err
		}
		found := false
		ms, _ := res["matches"].([]any)
		for _, m := range ms {
			found = found || m == command
		}
		if !found {
			return "", "", &APIError{Path: "/api/which", Msg: fmt.Sprintf("command not found: %q", command), Code: "command_not_found"}
		}
	}
	if command != "" {
		command, marker = gated(connectGate, command)
	}
	sid, err = c.open(cols, rows, cwd, command)
	return sid, marker, err
}

// Delete kills the remote session sid, best effort: the hangup a local
// session gives its remote one when its PTY ends.
func Delete(keysDir, id, sid string) {
	_, _ = Call(keysDir, id, "/api/sessions/"+sid, map[string]any{"_method": "DELETE"})
}

func (c *client) open(cols, rows int, cwd, command string) (string, error) {
	body := map[string]any{"_method": "POST", "cols": cols, "rows": rows}
	if cwd != "" {
		body["cwd"] = cwd
	}
	if command != "" {
		body["command"] = command
	}
	res, err := c.call("/api/sessions", body)
	if err != nil {
		return "", err
	}
	sid, _ := res["id"].(string)
	if sidBytes(sid) == nil {
		return "", errors.New("the remote returned no session id")
	}
	return sid, nil
}

// sidBytes is the 16-byte form of a session UUID that data frames carry.
func sidBytes(sid string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(sid, "-", ""))
	if err != nil || len(b) != 16 || len(sid) != 36 {
		return nil
	}
	return b
}

// relay attaches to the remote session sid and moves the stream until it
// exits: its output to out, in to its input, the exit code back. Behind a
// marker (a gated command) everything before the gate is dropped. tty is
// connect's raw terminal: SIGWINCH resizes, input is not closed with ^D.
// Any other signal deletes the session and returns 128+n; so does any way
// out but the session's own end.
func (c *client) relay(sid, marker string, in io.Reader, out io.Writer, sigs <-chan os.Signal, tty bool) (int, error) {
	sidBuf := sidBytes(sid)
	exited := false
	defer func() {
		if !exited {
			c.deleteSession(sid)
		}
	}()
	cols, rows := execCols, execRows
	if tty {
		cols, rows = ttySize()
	}
	if err := c.control(map[string]any{"type": "attach", "sid": sid, "cols": cols, "rows": rows}); err != nil {
		return 0, err
	}

	var pre []byte // output before the gate opens: the marker, attach noise
	gated, ready := marker == "", false
	var gateTimeout <-chan time.Time
	if gated {
		go c.pump(sidBuf, in, tty)
	} else {
		gateTimeout = time.After(replyTimeout)
	}
	code, haveCode := 0, false
	var grace <-chan time.Time
	for {
		select {
		case <-gateTimeout:
			return 0, errors.New("the remote command did not start")
		case sig := <-sigs:
			if tty && sig == syscall.SIGWINCH {
				cols, rows := ttySize()
				_ = c.control(map[string]any{"type": "resize", "sid": sid, "cols": cols, "rows": rows})
				continue
			}
			s, _ := sig.(syscall.Signal)
			return 128 + int(s), nil
		case <-grace:
			exited = true
			if !gated {
				_, _ = out.Write(pre) // it never started: the shell's own error
			}
			if !haveCode {
				return 0, errors.New("the remote session ended without an exit status")
			}
			return code, nil
		case p, ok := <-c.in:
			if !ok {
				return 0, c.closedErr()
			}
			typ, plain, err := c.decrypt(p)
			if err != nil {
				continue
			}
			if typ == frameData {
				if len(plain) < 16 || !bytes.Equal(plain[:16], sidBuf) {
					continue
				}
				if haveCode {
					grace = time.After(exitIdle)
				}
				if gated {
					if _, err := out.Write(plain[16:]); errors.Is(err, syscall.EPIPE) {
						return 128 + int(syscall.SIGPIPE), nil // `| head`: quiet, like a local pipeline
					} else if err != nil {
						return 0, err
					}
				} else if pre = append(pre, plain[16:]...); len(pre) > 1<<20 {
					return 0, errors.New("the remote command did not start")
				}
			} else {
				var m struct {
					Type, Sid, Signal string
					ExitCode          int
				}
				if json.Unmarshal(plain, &m) != nil || m.Sid != sid {
					continue
				}
				switch m.Type {
				case "ready":
					ready = true
				case "exit":
					code, haveCode = exitCode(m.ExitCode, m.Signal), true
					grace = time.After(exitIdle)
				case "gone":
					if grace == nil {
						grace = time.After(goneGrace)
					}
				}
			}
			if !gated && ready && bytes.Contains(pre, []byte(marker)) {
				gated, pre, gateTimeout = true, nil, nil
				if err := c.data(sidBuf, []byte("\n")); err != nil {
					return 0, err
				}
				go c.pump(sidBuf, in, tty)
			}
		}
	}
}

// pump sends in as terminal input. Piped (exec), it ends with ^D: one ends a
// last line without a newline, the next is EOF.
func (c *client) pump(sid []byte, in io.Reader, tty bool) {
	last := byte('\n')
	if in != nil {
		buf := make([]byte, 32<<10)
		for {
			n, err := in.Read(buf)
			if n > 0 {
				if c.data(sid, buf[:n]) != nil {
					return
				}
				last = buf[n-1]
			}
			if err != nil {
				break
			}
		}
	}
	if tty {
		return
	}
	eof := []byte{4}
	if last != '\n' {
		eof = []byte{4, 4}
	}
	_ = c.data(sid, eof)
}

// deleteSession kills the remote session; over a fresh connection when this
// one is gone (the remote revoked its token with the socket).
func (c *client) deleteSession(sid string) {
	del := map[string]any{"_method": "DELETE"}
	if _, err := c.call("/api/sessions/"+sid, del); err == nil {
		return
	}
	if c2, err := connect(c.r); err == nil {
		_, _ = c2.call("/api/sessions/"+sid, del)
		c2.close()
	}
}

// exitCode maps the exit frame like a shell: a signal name ("killed", as
// the remote's Go runtime spells it) becomes 128+n.
func exitCode(code int, signal string) int {
	if signal == "" {
		if code < 0 {
			return 255
		}
		return code
	}
	for n := 1; n < 65; n++ {
		if syscall.Signal(n).String() == signal {
			return 128 + n
		}
	}
	return 255
}
