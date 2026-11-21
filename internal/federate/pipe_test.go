// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate_test

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"shells/internal/federate"
	"shells/internal/federate/fedtest"
)

// lines is a Writer that hands each write to a channel.
type lines chan string

func (l lines) Write(p []byte) (int, error) { l <- string(p); return len(p), nil }

// gone waits up to d until pid no longer exists.
func gone(t *testing.T, pid int, d time.Duration) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return
		}
	}
	t.Errorf("remote process %d still alive after %v", pid, d)
}

// bgPid starts `sleep 30` in the background of a pipe exec and returns its
// pid and the exec's result.
func bgPid(t *testing.T, keys string, stdin io.Reader, sigs chan os.Signal) (int, chan result) {
	t.Helper()
	out := make(lines, 8)
	done := make(chan result, 1)
	go func() {
		code, err := federate.Run(keys, id, "sleep 30 & echo $!; wait", stdin, out, io.Discard, sigs)
		done <- result{code: code, err: err}
	}()
	pid, _ := strconv.Atoi(strings.TrimSpace(<-out))
	if pid < 2 {
		t.Fatal("no background pid")
	}
	return pid, done
}

// fds counts this process's open files (the remote runs in it too); -1
// where /proc is missing.
func fds() int {
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(e)
}

// settles waits until no more files are open than before.
func settles(t *testing.T, before int) {
	t.Helper()
	n := fds()
	for i := 0; i < 300 && n > before; i++ {
		time.Sleep(10 * time.Millisecond)
		n = fds()
	}
	if n > before {
		t.Errorf("%d files open, %d before: a leak", n, before)
	}
}

func TestPipeBinary(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	in := bytes.Repeat(all, 1024) // 256 KB: many frames, every byte value, ^D and CR among them
	if res := run(t, keys, "cat", string(in), nil); res.err != nil || res.code != 0 || res.out != string(in) {
		t.Errorf("cat of 0x00-0xff = %d, %d bytes, equal %v, %v", res.code, len(res.out), res.out == string(in), res.err)
	}
	if n := rm.Mgr.Count(); n != 0 {
		t.Errorf("pipe exec left %d PTY sessions", n)
	}
}

// TestPipeSidNotASession: the id reserved for pipe frames is refused where a
// session id is taken.
func TestPipeSidNotASession(t *testing.T) {
	if federate.SidBytes("00000000-0000-0000-0000-000000000000") != nil || federate.SidBytes(id) == nil {
		t.Error("sidBytes takes the pipe id, or refuses a session's")
	}
}

// TestPipeDropKillsGroup: a socket dropped mid-command (no close frame, as
// when the client is killed) kills the command's whole process group.
func TestPipeDropKillsGroup(t *testing.T) {
	rm := fedtest.Start(t)
	l := rm.Link(t, 0, 0)
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, l.URL, []byte(fedtest.Secret)); err != nil {
		t.Fatal(err)
	}
	before := fds()
	pid, done := bgPid(t, keys, nil, nil)
	l.Cut()
	if res := <-done; res.err == nil {
		t.Error("Run on a dropped socket returned no error")
	}
	gone(t, pid, 5*time.Second)
	settles(t, before)
}

// zeros is an endless stdin.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// TestPipeExitWhileStdin: a command that ends while the client still pushes
// stdin returns its whole output and status; the remote's close behind exit
// must not turn into a TCP reset that drops them, directly or over a delay.
// 25 runs per remote: it takes 30 connects a minute per IP.
func TestPipeExitWhileStdin(t *testing.T) {
	in := bytes.Repeat([]byte("x"), 8<<20)
	for _, delay := range []time.Duration{0, 0, 5 * time.Millisecond, 5 * time.Millisecond} {
		rm := fedtest.Start(t)
		url := rm.URL
		if delay > 0 {
			url = rm.Link(t, 0, delay).URL
		}
		keys := filepath.Join(rm.Dir, "ssh-keys")
		if err := federate.Setup(keys, id, url, []byte(fedtest.Secret)); err != nil {
			t.Fatal(err)
		}
		lost := 0
		for range 25 {
			var out bytes.Buffer
			code, err := federate.Run(keys, id, "head -c 1; exit 5", bytes.NewReader(in), &out, io.Discard, nil)
			if err != nil || code != 5 || out.String() != "x" {
				lost++
			}
		}
		if lost > 0 {
			t.Errorf("delay %v: %d of 25 runs lost the output or the status", delay, lost)
		}
	}
}

// TestPipeDropStuckStdin: a client dropped while the remote is parked on a
// stdin the command does not read is found by the remote's pings, within two.
func TestPipeDropStuckStdin(t *testing.T) {
	rm := fedtest.Start(t)
	l := rm.Link(t, 0, 0)
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, l.URL, []byte(fedtest.Secret)); err != nil {
		t.Fatal(err)
	}
	pid, done := bgPid(t, keys, zeros{}, nil)
	time.Sleep(300 * time.Millisecond) // stdin fills: the remote's readLoop parks
	l.Cut()
	<-done
	gone(t, pid, 8*time.Second)
}

// TestPipeTamper: a relay that terminates TLS replays, drops or reorders
// pipe frames: the connection closes with an error, and nothing runs twice.
func TestPipeTamper(t *testing.T) {
	rm := fedtest.Start(t)
	var mu sync.Mutex // the relay's goroutines of a run may outlive it
	tamper := func(_ bool, p []byte) [][]byte { return [][]byte{p} }
	relay := rm.Relay(t, func(up bool, p []byte) [][]byte { mu.Lock(); defer mu.Unlock(); return tamper(up, p) }, nil)
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, relay, []byte(fedtest.Secret)); err != nil {
		t.Fatal(err)
	}
	if res := run(t, keys, "echo ok", "", nil); res.err != nil || res.code != 0 || res.out != "ok\n" {
		t.Fatalf("through an honest relay = %+v", res)
	}
	f := filepath.Join(rm.Dir, "f")
	var held []byte
	n := 0 // binary frames seen in the tampered direction
	set := func(fn func(up bool, p []byte) [][]byte) {
		mu.Lock()
		n, held, tamper = 0, nil, fn
		mu.Unlock()
	}

	// A replayed stdin frame, stdin kept open: only its seq can tell.
	set(func(up bool, p []byte) [][]byte {
		if up && p[0] == 0 {
			if n++; n == 1 {
				return [][]byte{p, p}
			}
		}
		return [][]byte{p}
	})
	pr, pw := io.Pipe()
	go pw.Write([]byte("echo once >> " + f + "\n"))
	done := make(chan result, 1)
	go func() {
		code, err := federate.Run(keys, id, "sh", pr, io.Discard, io.Discard, nil)
		done <- result{code: code, err: err}
	}()
	select {
	case res := <-done:
		if res.err == nil && res.code == 0 {
			t.Errorf("replayed stdin: ended 0, want an error")
		}
	case <-time.After(3 * time.Second):
		t.Errorf("replayed stdin: unnoticed")
		pw.Close()
		<-done
	}
	if b, _ := os.ReadFile(f); strings.Count(string(b), "once") > 1 {
		t.Errorf("a replayed stdin ran the command twice: %q", b)
	}

	for _, tc := range []struct {
		name, cmd, stdin string
		tamper           func(up bool, p []byte) [][]byte
	}{
		{"the only stdout frame dropped", "echo hi", "", func(up bool, p []byte) [][]byte { // only exit's total can tell
			if !up && p[0] == 0 {
				return nil
			}
			return [][]byte{p}
		}},
		{"stdout frames reordered", "seq 1 30000", "", func(up bool, p []byte) [][]byte { // totals match: only seq can tell
			if up || p[0] != 0 {
				return [][]byte{p}
			}
			switch n++; n {
			case 2:
				held = p
				return nil
			case 3:
				return [][]byte{p, held}
			}
			return [][]byte{p}
		}},
		{"the only stdin frame dropped", "cat", "data", func(up bool, p []byte) [][]byte { // only stdin-eof's total can tell
			if up && p[0] == 0 {
				return nil
			}
			return [][]byte{p}
		}},
		{"stdin-eof before stdin", "cat", "data", func(up bool, p []byte) [][]byte {
			if !up {
				return [][]byte{p}
			}
			if p[0] == 0 && held == nil {
				held = p
				return nil
			}
			if held != nil {
				q := held
				held = nil
				return [][]byte{p, q}
			}
			return [][]byte{p}
		}},
	} {
		set(tc.tamper)
		if res := run(t, keys, tc.cmd, tc.stdin, nil); res.err == nil && res.code == 0 {
			t.Errorf("%s: %q ended 0 with %d bytes out, want an error", tc.name, tc.cmd, len(res.out))
		}
	}
}

// TestPipeOwnSession: the command leads a session of its own (no
// controlling tty to stop it on SIGTTOU when the server runs in a terminal).
func TestPipeOwnSession(t *testing.T) {
	if _, err := exec.LookPath("ps"); err != nil {
		t.Skip("no ps")
	}
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	res := run(t, keys, "echo $$; ps -o sid= -p $$", "", nil)
	if f := strings.Fields(res.out); res.err != nil || len(f) != 2 || f[0] != f[1] {
		t.Errorf("pid and session = %q, %v; want equal", res.out, res.err)
	}
}

// TestPipeKillPipes: the server's stop and restart kill running pipe execs.
func TestPipeKillPipes(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	pid, done := bgPid(t, keys, nil, nil)
	rm.WS.KillPipes()
	if res := <-done; res.err != nil || res.code != 137 {
		t.Errorf("exec after KillPipes = %+v, want 137", res)
	}
	gone(t, pid, 5*time.Second)
	// One that starts while the server stops dies at once, never orphaned.
	if res := run(t, keys, "sleep 5; echo late", "", nil); res.code != 137 || res.out != "" {
		t.Errorf("exec during the stop = %+v, want 137 and no output", res)
	}
}

// TestPipeSIGPIPE: SIGPIPE comes from a write to a broken socket, not from
// the user: the exec goes on (a closed stdout is the write's EPIPE).
func TestPipeSIGPIPE(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(chan os.Signal, 1)
	sigs <- syscall.SIGPIPE
	if res := run(t, keys, "sleep 0.3; echo done", "", sigs); res.err != nil || res.code != 0 || res.out != "done\n" {
		t.Errorf("exec with a SIGPIPE = %+v", res)
	}
}

// TestExecEmptyCommand: `shells exec <name> ""` is bad usage, not a wait.
func TestExecEmptyCommand(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range [][]string{{""}, {"--", " "}} {
		done := make(chan int, 1)
		go func() {
			done <- federate.Main(append([]string{"exec", "box"}, cmd...), keys, func(string) (string, error) { return id, nil })
		}()
		select {
		case code := <-done:
			if code != 2 {
				t.Errorf("exec %q = %d, want 2", cmd, code)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("exec %q hung", cmd)
		}
	}
}

func TestPipeSignal(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	out := make(lines, 8)
	sigs := make(chan os.Signal, 1)
	done := make(chan int, 1)
	go func() {
		code, _ := federate.Run(keys, id, "sleep 30 & echo $!; wait", nil, out, io.Discard, sigs)
		done <- code
	}()
	pid, _ := strconv.Atoi(strings.TrimSpace(<-out))
	sigs <- syscall.SIGINT
	if code := <-done; code != 130 {
		t.Errorf("SIGINT = %d, want 130", code)
	}
	gone(t, pid, 5*time.Second)
}

// TestPipeMaxSessions: pipe execs count against MaxSessions (4 in fedtest)
// and give their slot back when they end.
func TestPipeMaxSessions(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	run(t, keys, "true", "", nil) // warm: what stays open across execs
	before := fds()
	var stdins []*io.PipeWriter
	codes := make(chan int, 4)
	for range 4 {
		pr, pw := io.Pipe()
		stdins = append(stdins, pw)
		out := make(lines, 8)
		go func() {
			code, _ := federate.Run(keys, id, "echo up; cat", pr, out, io.Discard, nil)
			codes <- code
		}()
		<-out
	}
	if res := run(t, keys, "true", "", nil); res.err == nil || !strings.Contains(res.err.Error(), "max sessions") {
		t.Errorf("a fifth exec = %+v, want max sessions", res)
	}
	for _, pw := range stdins {
		pw.Close()
	}
	for range 4 {
		if code := <-codes; code != 0 {
			t.Errorf("cat ended %d", code)
		}
	}
	if res := run(t, keys, "exit 7", "", nil); res.err != nil || res.code != 7 { // the slot is free before exit is sent
		t.Errorf("exec after the others ended = %+v", res)
	}
	settles(t, before)
}

// TestPipeSlowLink: behind 32 KB/s, 300 ms each way and a 1 s stall, a
// command's output that outruns the link many times over comes back whole:
// the remote stops reading the pipe instead of dropping output.
func TestPipeSlowLink(t *testing.T) {
	if testing.Short() {
		t.Skip("about 75 s")
	}
	rm := fedtest.Start(t)
	l := rm.Link(t, 32<<10, 300*time.Millisecond)
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, l.URL, []byte(fedtest.Secret)); err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	for i := 1; i <= 300000; i++ {
		want.WriteString(strconv.Itoa(i) + "\n")
	}
	time.AfterFunc(5*time.Second, func() { l.Stall(time.Second) })
	var out bytes.Buffer
	code, err := federate.Run(keys, id, "seq 300000; exit 3", nil, &out, io.Discard, nil)
	if err != nil || code != 3 || !bytes.Equal(out.Bytes(), want.Bytes()) {
		t.Errorf("seq 300000 = %d, %d of %d bytes, equal %v, %v", code, out.Len(), want.Len(), bytes.Equal(out.Bytes(), want.Bytes()), err)
	}
	if code, err := federate.Run(keys, id, "sleep 5; exit 4", nil, io.Discard, io.Discard, nil); err != nil || code != 4 {
		t.Errorf("sleep 5; exit 4 = %d, %v", code, err)
	}
}
