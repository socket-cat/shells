// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"shells/internal/config"
)

// On a remote without pipe mode (from before caps "pipe") exec's remote side
// is a PTY (the PTY ceiling): stdout and stderr arrive merged, stdin is a tty
// (text piped in is sent, then ^D; binary is unsupported). Wide so tools do
// not cut lines to 80 columns.
const execCols, execRows = 200, 50

// A gate runs before a command and holds it until the client is attached:
// the remote destroys a session the moment its process exits, so a quick
// command would be gone, output and exit status with it, before `attach`
// arrives. head waits for the line the client sends right behind `attach`;
// the remote handles one connection's frames in order, so it is attached
// before that line reaches the PTY (no round trip spent waiting). The
// marker, split by an empty quoted string so the command text never
// contains it, follows that line: it lands behind everything the remote
// sends while attaching (replay, mode restore), so what comes after it is
// the command's. The command goes through eval, so the outer shell parses
// only the gate: a command it cannot parse fails after the gate, error and
// status intact. Plain external commands, ';', eval and single quotes only,
// so it parses in sh, bash, zsh and fish (fish alone reads a backslash
// inside single quotes as an escape).
//
// execGate also keeps echo off (stdin piped in is not echoed back) and drops
// the CR the PTY puts before each LF; connectGate gives the terminal back.
// execGate runs the command in a child of the same shell under sh, which
// then prints an end marker and exits with the child's status: in-band, so
// the marker follows all the command's output however the remote orders its
// frames (a remote before pipe mode can send exit ahead of the output's
// tail), and `exit` or a signal in the command ends only the child. The
// status comes from the authenticated exit frame, never from the marker.
// ponytail: the nonce rides in the wrapper's argv ($0), so another user on
// the remote who can read its /proc/<pid>/cmdline can print the marker early
// and cut the output short (not change the status); inherent to the PTY
// path, gone with pipe mode.
const (
	execGate    = "stty -echo -onlcr; head -n 1 >/dev/null; printf shells-go''-%[1]s; exec sh -c '\"${SHELL:-sh}\" -c \"$1\"; s=$?; printf shells-end-%%s \"$0\"; exit $s' %[1]s '%[2]s'"
	connectGate = "stty -echo; head -n 1 >/dev/null; stty echo; printf shells-go''-%[1]s; eval '%[2]s'"
)

// gated wraps cmd in gate; marker is the nonce its marker carries.
func gated(gate, cmd string) (command, marker string) {
	var n [8]byte
	_, _ = rand.Read(n[:])
	marker = hex.EncodeToString(n[:])
	return fmt.Sprintf(gate, marker, strings.ReplaceAll(cmd, "'", `'\''`)), marker
}

// exitIdle is how long connect keeps reading after the exit frame, and after
// each output frame behind it: the remote flushes its last coalesced output
// up to one 8 ms tick after sending exit.
// ponytail: a timing bound (the tick plus scheduling and network jitter, not
// a slow link or a retransmitted packet) for an interactive session's last
// screen; exec waits for its end marker instead (tailWait).
const exitIdle = 25 * time.Millisecond

// tailWait is how long a gated exec waits for its end marker after the exit
// frame (or gone), renewed by each output frame, or for the exit frame
// after the marker: a slow link delivers the tail late. No marker by then
// means the remote lost the tail: an error, never a short exit 0.
const tailWait = 10 * time.Second

// ender passes a gated exec's output on up to its end marker; a marker
// split across frames is held back until whole.
type ender struct {
	w         io.Writer
	end, held []byte
}

func (e *ender) write(b []byte) (done bool, err error) {
	e.held = append(e.held, b...)
	if i := bytes.Index(e.held, e.end); i >= 0 {
		_, err = e.w.Write(e.held[:i])
		return err == nil, err
	}
	if k := len(e.held) - len(e.end) + 1; k > 0 {
		_, err = e.w.Write(e.held[:k])
		e.held = append(e.held[:0], e.held[k:]...)
	}
	return false, err
}

// goneGrace is how long the client waits for the exit frame after the
// session is gone (the remote sends "gone" first).
const goneGrace = 2 * time.Second

// Run runs cmd on the remote id, like `ssh host cmd`: its stdout and stderr
// to ours, stdin to its EOF, the remote exit code returned. A signal on sigs
// ends it (the remote kills it, or deletes its session) and returns 128+n.
// Without pipe mode the PTY ceiling applies: stderr comes merged into stdout.
func Run(keysDir, id, cmd string, stdin io.Reader, stdout, stderr io.Writer, sigs <-chan os.Signal) (int, error) {
	r, err := load(keysDir, id)
	if err != nil {
		return 0, err
	}
	c, err := connect(r, false, cmd)
	if err != nil {
		return 0, err
	}
	if c.pipe { // cmd already runs; stdin starts only now, so a PTY fallback would have lost none
		code, err := c.pipeRelay(stdin, stdout, stderr, sigs)
		c.ws.Close(1000, "") // no wait for the echo: a remote parked on our stdin sends none, its pings find the socket gone
		return code, err
	}
	defer c.close()
	command, marker := gated(execGate, cmd) // the remote ignored connect's exec
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
	c, err := connect(r, true, "")
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

// pipeSid is the reserved session id whose data frames carry pipe mode's
// streams (wshandler pipeSid): pipeSid || fd || seq || bytes, seq a
// big-endian count of the frames sent before in that direction; stdin-eof
// and exit carry the totals. Never a session's.
const pipeSid = "00000000-0000-0000-0000-000000000000"

const pipeHdr = 16 + 1 + 8

// errOutOfSequence: pipe frames came replayed, dropped or reordered (a relay
// that terminates TLS can do that to the stream crypto); the output is not
// to be trusted, and closing the socket kills the command.
var errOutOfSequence = errors.New("the remote's frames arrived out of sequence (replayed, dropped or reordered on the way): stopped")

var pipeSidBuf, _ = hex.DecodeString(strings.ReplaceAll(pipeSid, "-", ""))

// sidBytes is the 16-byte form of a session UUID that data frames carry; nil
// for pipeSid.
func sidBytes(sid string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(sid, "-", ""))
	if err != nil || len(b) != 16 || len(sid) != 36 || sid == pipeSid {
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

	var pre []byte // output before the command: attach replay, the marker
	start := []byte("shells-go-" + marker)
	gated := marker == ""
	write := func(b []byte) (bool, error) { _, err := out.Write(b); return false, err }
	idle := exitIdle
	if !tty && marker != "" {
		e := &ender{w: out, end: []byte("shells-end-" + marker)}
		write, idle = e.write, tailWait
	}
	ended := false // the end marker came: the command's output is all out
	var gateTimeout <-chan time.Time
	if gated {
		go c.pump(sidBuf, in, tty)
	} else {
		if err := c.data(sidBuf, []byte("\n")); err != nil {
			return 0, err
		}
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
			if sig == syscall.SIGPIPE {
				continue // a write to a broken socket; a closed stdout is out.Write's EPIPE
			}
			s, _ := sig.(syscall.Signal)
			return 128 + int(s), nil
		case <-grace:
			exited = true
			if !gated {
				_, _ = out.Write(pre) // it never started: the shell's own error
			} else if idle == tailWait && !ended {
				return 0, errors.New("the remote's output stopped before its end marker: its tail was lost, the output is incomplete")
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
					grace = time.After(idle)
				}
				if gated && !ended {
					if done, err := write(plain[16:]); errors.Is(err, syscall.EPIPE) {
						return 128 + int(syscall.SIGPIPE), nil // `| head`: quiet, like a local pipeline
					} else if err != nil {
						return 0, err
					} else if ended = done; ended && haveCode {
						exited = true
						return code, nil
					} else if ended {
						grace = time.After(tailWait) // for the exit frame
					}
				} else if !gated {
					if pre = append(pre, plain[16:]...); len(pre) > 1<<20 {
						return 0, errors.New("the remote command did not start")
					}
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
				case "exit":
					code, haveCode = exitCode(m.ExitCode, m.Signal), true
					if ended {
						exited = true
						return code, nil
					}
					grace = time.After(idle)
				case "gone":
					if grace == nil {
						grace = time.After(max(goneGrace, idle))
					}
				}
			}
			if i := bytes.Index(pre, start); !gated && i >= 0 {
				gated, gateTimeout = true, nil
				if done, err := write(pre[i+len(start):]); errors.Is(err, syscall.EPIPE) {
					return 128 + int(syscall.SIGPIPE), nil
				} else if err != nil {
					return 0, err
				} else if ended = done; ended && haveCode {
					exited = true
					return code, nil
				} else if ended {
					grace = time.After(tailWait)
				}
				pre = nil
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

// pipeRelay moves the pipe exec connect started: stdout and stderr frames to
// their writers, in to the remote's stdin. exit is the stream's last frame,
// so it ends the relay with nothing left behind it. Any other way out drops
// the socket, and the remote kills the command's process group with it.
func (c *client) pipeRelay(in io.Reader, stdout, stderr io.Writer, sigs <-chan os.Signal) (int, error) {
	go c.pumpPipe(in)
	var seq uint64 // output frames taken
	for {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGPIPE {
				continue // a write to a broken socket; a closed stdout is w.Write's EPIPE
			}
			s, _ := sig.(syscall.Signal)
			return 128 + int(s), nil
		case p, ok := <-c.in:
			if !ok {
				return 0, c.closedErr()
			}
			typ, plain, err := c.decrypt(p)
			if err != nil {
				continue
			}
			if typ == frameData {
				if len(plain) < pipeHdr || !bytes.Equal(plain[:16], pipeSidBuf) {
					continue
				}
				if binary.BigEndian.Uint64(plain[17:pipeHdr]) != seq {
					return 0, errOutOfSequence
				}
				seq++
				w := stdout
				if plain[16] == 2 {
					w = stderr
				} else if plain[16] != 1 {
					continue
				}
				if _, err := w.Write(plain[pipeHdr:]); errors.Is(err, syscall.EPIPE) {
					return 128 + int(syscall.SIGPIPE), nil
				} else if err != nil {
					return 0, err
				}
				continue
			}
			var m struct {
				Type, Signal, Error string
				ExitCode            int
				N                   uint64
			}
			if typ == frameControl && json.Unmarshal(plain, &m) == nil && m.Type == "exit" {
				if m.Error != "" {
					return 0, errors.New("the remote: " + m.Error)
				}
				if m.N != seq {
					return 0, errOutOfSequence
				}
				return exitCode(m.ExitCode, m.Signal), nil
			}
		}
	}
}

// pumpPipe sends in as the remote's stdin, then stdin-eof. Past WSHWM queued
// it waits for WSLWM, so a fast in on a slow link waits in the pipe it comes
// from, not in memory.
func (c *client) pumpPipe(in io.Reader) {
	var seq uint64
	if in != nil {
		buf := make([]byte, pipeHdr+32<<10) // pipeSid, fd 0, seq, bytes
		copy(buf, pipeSidBuf)
		for c.ws.WaitDrain(config.WSHWM, config.WSLWM) {
			n, err := in.Read(buf[pipeHdr:])
			if n > 0 {
				binary.BigEndian.PutUint64(buf[17:pipeHdr], seq)
				if c.send(frameData, buf[:pipeHdr+n]) != nil {
					return
				}
				seq++
			}
			if err != nil {
				break
			}
		}
	}
	_ = c.control(map[string]any{"type": "stdin-eof", "n": seq})
}

// deleteSession kills the remote session; over a fresh connection when this
// one is gone (the remote revoked its token with the socket).
func (c *client) deleteSession(sid string) {
	del := map[string]any{"_method": "DELETE"}
	if _, err := c.call("/api/sessions/"+sid, del); err == nil {
		return
	}
	if c2, err := connect(c.r, true, ""); err == nil {
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
