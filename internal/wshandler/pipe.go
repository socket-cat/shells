// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package wshandler

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"shells/internal/util"
)

// pipeSid is the reserved session id whose data frames carry pipe exec's
// streams: plaintext pipeSid || fd || seq || bytes, fd 0 (stdin) from the
// client, 1 (stdout) and 2 (stderr) from the remote. On the wire a pipe frame
// is a data frame like a terminal's; the stream is inside the ciphertext. All
// zero, never a session's (util.NewUUID sets the version bits), and a remote
// from before pipe mode drops it as an unknown session.
const pipeSid = "00000000-0000-0000-0000-000000000000"

// pipeHdr is pipeSid, fd and seq: a big-endian count of the frames sent
// before in that direction. The stream crypto has no counter, so a relay
// that terminates TLS could replay, drop or reorder frames; seq and the
// totals in stdin-eof and exit catch it, and the connection closes.
const pipeHdr = 16 + 1 + 8

// pipePing is how often a readLoop parked on a stdin the command does not
// read pings the client: a client gone with a reset socket is found at the
// next failed write, not at the 60 s read deadline that cannot run there.
// ponytail: a peer that vanished without a reset (power, cable) is found only
// when TCP gives up retransmitting (minutes).
const pipePing = 2 * time.Second

// pipeProc is a command run by the `exec` control: `$SHELL -c cmd` on os/exec
// pipes, no PTY and no session.Manager. It lives and dies with its socket.
type pipeProc struct {
	cmd            *exec.Cmd
	stdout, stderr io.ReadCloser
	in             chan []byte // stdin frames, unbuffered: one in flight; readLoop is the only sender and closes it
	inClosed       bool        // readLoop only
	inSeq          uint64      // readLoop only: stdin frames taken
	outMu          sync.Mutex  // seq and queue order of the two output readers
	outSeq         uint64
	reaped         atomic.Bool // from here on a dropped socket leaves the group alone, like ssh
}

// kill ends the command's process group (Setsid: pgid == pid) while it runs.
// ponytail: a child that made its own group or session (job control,
// setsid, a daemon) escapes it; upgrade: kill by session (a /proc sid scan on
// Linux) or contain the command (subreaper, cgroup).
func (p *pipeProc) kill() {
	if !p.reaped.Load() {
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	}
}

// handleExec starts cmd, one per connection, counted against MaxSessions
// with the PTY sessions. Each pipe is read only while the socket queue is
// under WSHWM (resuming under WSLWM): a full pipe blocks the command instead
// of dropping output. exit goes out once both pipes reached EOF and their
// frames are queued, so it is the stream's last frame, and the socket closes
// behind it.
func (cc *ClientConn) handleExec(msg map[string]any) {
	command, _ := msg["cmd"].(string)
	if command == "" || cc.token == "" || cc.handler.NoPipe { // no token: the auth store refused this socket
		return
	}
	if cc.pipe.Load() != nil {
		cc.pipeAbort() // a second exec is a replay
		return
	}
	h := cc.handler
	// ponytail: pipes count when an exec starts; a PTY session created later
	// does not count them, so the total can pass the cap by the pipes running.
	if n := h.pipes.Add(1); h.manager.Count()+int(n) > cc.cfg.MaxSessions {
		h.pipes.Add(-1)
		cc.sendPipeExit(map[string]any{"error": fmt.Sprintf("max sessions (%d) reached", cc.cfg.MaxSessions)})
		return
	}
	shell := cc.cfg.DefaultShell
	cmd := exec.Command(shell, "-c", command)
	cmd.Dir = cc.cfg.Cwd
	cmd.Env = []string{"SHELL=" + shell, "PWD=" + cmd.Dir}
	for _, k := range cc.cfg.ShellEnvKeys {
		if v := os.Getenv(k); v != "" && k != "SHELL" && k != "PWD" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	// A session of its own: no controlling tty, so nothing stops on SIGTTOU
	// when the server runs in a terminal, and pgid == pid for kill.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	p := &pipeProc{cmd: cmd, in: make(chan []byte)}
	stdin, err := cmd.StdinPipe()
	if err == nil {
		p.stdout, err = cmd.StdoutPipe()
	}
	if err == nil {
		p.stderr, err = cmd.StderrPipe()
	}
	if err != nil {
		cmd.Err = err // Start then fails at once and closes the pipes made so far
	}
	if err = cmd.Start(); err != nil {
		h.pipes.Add(-1)
		cc.sendPipeExit(map[string]any{"error": err.Error()})
		return
	}
	cc.pipe.Store(p)
	if h.stopping.Load() {
		p.kill() // KillPipes ran between Start and Store
	}

	go func() {
		var werr error
		for {
			select {
			case b, ok := <-p.in:
				if !ok {
					_ = stdin.Close()
					return
				}
				if werr == nil {
					_, werr = stdin.Write(b) // after an error: drain, so readLoop never blocks on a dead stdin
				}
			case <-cc.ws.Done():
				_ = stdin.Close()
				return
			}
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	for fd, r := range []io.Reader{p.stdout, p.stderr} {
		go func() {
			defer wg.Done()
			buf := make([]byte, pipeHdr+32<<10)
			copy(buf, sidToBytes(pipeSid))
			buf[16] = byte(fd + 1)
			for cc.ws.WaitDrain(int64(cc.cfg.WSHWM), int64(cc.cfg.WSLWM)) {
				n, err := r.Read(buf[pipeHdr:])
				if n > 0 {
					p.outMu.Lock()
					binary.BigEndian.PutUint64(buf[17:pipeHdr], p.outSeq)
					p.outSeq++
					cc.sendFrame(buf[:pipeHdr+n], msgTypeData)
					p.outMu.Unlock()
				}
				if err != nil {
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		_ = cmd.Wait()
		p.reaped.Store(true)
		h.pipes.Add(-1)
		code, signal := cmd.ProcessState.ExitCode(), ""
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			signal = ws.Signal().String()
		}
		cc.sendPipeExit(map[string]any{"exitCode": code, "signal": signal, "n": p.outSeq})
	}()
}

// pipeInput hands a stdin frame (fd || seq || bytes) to the writer, blocking
// readLoop while the command does not read: TCP then holds the client back.
// A frame out of sequence, before exec or after stdin-eof aborts.
func (cc *ClientConn) pipeInput(data []byte) {
	if cc.handler.NoPipe {
		return
	}
	p := cc.pipe.Load()
	if p == nil || p.inClosed || len(data) < pipeHdr-16 || data[0] != 0 || binary.BigEndian.Uint64(data[1:9]) != p.inSeq {
		cc.pipeAbort()
		return
	}
	p.inSeq++
	select {
	case p.in <- data[9:]:
		return
	default:
	}
	t := time.NewTicker(pipePing)
	defer t.Stop()
	for {
		select {
		case p.in <- data[9:]:
			return
		case <-cc.ws.Done():
			return
		case <-t.C:
			cc.ws.SendPing(nil)
		}
	}
}

// pipeEOF closes stdin once n, the client's count of stdin frames, matches.
func (cc *ClientConn) pipeEOF(msg map[string]any) {
	if cc.handler.NoPipe {
		return
	}
	p := cc.pipe.Load()
	if p == nil || p.inClosed || util.IntFromAny(msg["n"]) != int(p.inSeq) {
		cc.pipeAbort()
		return
	}
	p.inClosed = true
	close(p.in)
}

// pipeAbort ends a pipe exec whose frames were replayed, dropped or
// reordered: the command dies before acting on more, and the socket closes.
func (cc *ClientConn) pipeAbort() {
	if p := cc.pipe.Load(); p != nil {
		p.inClosed = true
	}
	cc.pipeDrop()
	cc.ws.Close(1008, "pipe frames out of sequence")
}

// pipeDrop runs with the socket's cleanup: a command still running loses its
// process group, and closing the pipes frees the readers from a child that
// left the group holding them.
func (cc *ClientConn) pipeDrop() {
	if p := cc.pipe.Load(); p != nil {
		p.kill()
		_ = p.stdout.Close()
		_ = p.stderr.Close()
	}
}

// KillPipes kills every running pipe exec: the server is stopping or
// restarting, and they would outlive it.
// ponytail: a server killed with SIGKILL (or OOM) still orphans them:
// reparented to init, they live on beside the restarted server until their
// next write; upgrade: Pdeathsig (Linux only, needs LockOSThread on the
// spawning thread; a compound command's children need a subreaper or a
// cgroup), or the restarted server killing pipe groups it no longer owns.
func (h *Handler) KillPipes() {
	h.stopping.Store(true)
	h.forEachClient(func(cc *ClientConn) {
		if p := cc.pipe.Load(); p != nil {
			p.kill()
		}
	})
}

// sendPipeExit sends exit and closes the socket behind it: a relay that
// drops exit then ends the client too, never a hang.
func (cc *ClientConn) sendPipeExit(m map[string]any) {
	m["type"] = "exit"
	b, _ := json.Marshal(m)
	cc.sendEncrypted(b, nil)
	cc.ws.CloseDrain(1000, "")
}
