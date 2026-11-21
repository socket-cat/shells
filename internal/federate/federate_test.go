// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"shells/internal/federate"
	"shells/internal/federate/fedtest"
)

const id = "0b7a3c52-5d1e-4f6a-9c3b-2e8d7f1a4b60"

// setup stores the remote's credential as the picker's ssh-setup does, from
// a URL with a path (dropped) and the given secret.
func setup(t *testing.T, rm *fedtest.Remote, secret string) (string, error) {
	t.Helper()
	keys := filepath.Join(rm.Dir, "ssh-keys")
	return keys, federate.Setup(keys, id, rm.URL+"/some/path", []byte(secret))
}

type result struct {
	code        int
	out, errOut string
	err         error
}

func run(t *testing.T, keys, cmd, stdin string, sigs chan os.Signal) result {
	t.Helper()
	done := make(chan result, 1)
	go func() {
		var out, errOut bytes.Buffer
		code, err := federate.Run(keys, id, cmd, strings.NewReader(stdin), &out, &errOut, sigs)
		done <- result{code, out.String(), errOut.String(), err}
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(20 * time.Second):
		t.Fatalf("run %q hung", cmd)
		return result{}
	}
}

func TestSetupRun(t *testing.T) {
	rm := fedtest.Start(t)
	if err := federate.Probe(rm.URL); err != nil {
		t.Fatalf("probe: %v", err)
	}
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(keys, id+".shells")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode %v", p, st.Mode().Perm())
	}
	if bytes.Contains(raw, []byte(fedtest.Secret)) || !bytes.Contains(raw, []byte(`"url": "`+rm.URL+`"`)) || !bytes.Contains(raw, []byte(`"tlsPin": "`)) {
		t.Fatalf("%s = %s", p, raw)
	}

	for _, tc := range []struct {
		cmd, stdin, out, errOut string
		code                    int
	}{
		{"echo hi; exit 3", "", "hi\n", "", 3},
		{"echo a; sleep 0.001; echo b", "", "a\nb\n", "", 0},
		{"cat; echo done", "a\nb", "a\nbdone\n", "", 0}, // stdin-eof ends cat, not the command
		{"echo out; echo err >&2", "", "out\n", "err\n", 0},
		{`echo 'it''s' "a'b"`, "", "its a'b\n", "", 0},
		{"kill -9 $$", "", "", "", 137}, // a signal is 128+n
	} {
		res := run(t, keys, tc.cmd, tc.stdin, nil)
		if res.err != nil || res.code != tc.code || res.out != tc.out || res.errOut != tc.errOut {
			t.Errorf("run %q = %d %q %q %v, want %d %q %q", tc.cmd, res.code, res.out, res.errOut, res.err, tc.code, tc.out, tc.errOut)
		}
	}
	if res := run(t, keys, "echo 'unterminated", "", nil); res.err != nil || res.code == 0 || !strings.Contains(res.errOut, "nterminated") {
		t.Errorf("syntax error = %d %q %v", res.code, res.errOut, res.err)
	}
	if out, err := federate.Call(keys, id, "/api/ls", map[string]any{"path": rm.Dir}); err != nil || out["path"] == nil {
		t.Errorf("forwarded /api/ls = %v, %v", out, err)
	}
	png := base64.StdEncoding.EncodeToString(append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...))
	if out, err := federate.Call(keys, id, "/api/paste-image", map[string]any{"image": png, "name": "x.png"}); err != nil {
		t.Errorf("forwarded /api/paste-image: %v", err)
	} else if p, _ := out["path"].(string); !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, ".png") {
		t.Errorf("forwarded /api/paste-image path = %q", p)
	} else if _, err := os.Stat(p); err != nil {
		t.Errorf("pasted file: %v", err)
	} else {
		_ = os.Remove(p)
	}
	if n := rm.Mgr.Count(); n != 0 {
		t.Errorf("%d remote sessions left", n)
	}
}

// TestRunPTYFallback: a remote without caps "pipe" ignores the exec the
// client sends before it knows the caps and runs the command once, in a PTY
// behind the gate, with the PTY ceiling and none of stdin lost.
func TestRunPTYFallback(t *testing.T) {
	rm := fedtest.StartNoPipe(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cmd, stdin, out string
		code            int
	}{
		{"echo hi; exit 3", "", "hi\n", 3},
		{"echo a; sleep 0.001; echo b", "", "a\nb\n", 0}, // b is flushed after the exit frame
		{"cat", "a\nb", "a\nb", 0},                       // stdin sent, then ^D; not echoed back
		{"cat", strings.Repeat("0123456789abcdef\n", 200), strings.Repeat("0123456789abcdef\n", 200), 0},
		{"echo out; echo err >&2", "", "out\nerr\n", 0}, // merged streams
		{`echo 'it''s' "a'b"`, "", "its a'b\n", 0},      // quotes survive the eval quoting
	} {
		res := run(t, keys, tc.cmd, tc.stdin, nil)
		if res.err != nil || res.code != tc.code || res.out != tc.out || res.errOut != "" {
			t.Errorf("run %q = %d %q %q %v, want %d %q", tc.cmd, res.code, res.out, res.errOut, res.err, tc.code, tc.out)
		}
	}
	// A command the remote shell cannot parse fails after the gate: its
	// error and status come back.
	if res := run(t, keys, "echo 'unterminated", "", nil); res.err != nil || res.code == 0 || !strings.Contains(res.out, "nterminated") {
		t.Errorf("syntax error = %d %q %v", res.code, res.out, res.err)
	}
	// A signal ends only the command's shell; sh reports it as a local one would.
	if res := run(t, keys, "kill -9 $$", "", nil); res.err != nil || res.code != 137 {
		t.Errorf("kill -9 $$ = %+v, want 137", res)
	}
	ran := filepath.Join(rm.Dir, "ran")
	if res := run(t, keys, "echo x >> "+ran, "", nil); res.err != nil || res.code != 0 {
		t.Errorf("append = %+v", res)
	}
	if b, _ := os.ReadFile(ran); string(b) != "x\n" {
		t.Errorf("the command ran %q, want once", b)
	}
	if n := rm.Mgr.Count(); n != 0 {
		t.Errorf("%d remote sessions left", n)
	}
}

// TestRunPTYFallbackSlowLink: on a pre-pipe remote the exit frame can
// overtake the output's tail (its 8 ms coalescing); behind 10 Mbit/s the
// client must still return all of it, or fail, never exit 0 short.
func TestRunPTYFallbackSlowLink(t *testing.T) {
	rm := fedtest.StartNoPipe(t)
	l := rm.Link(t, 1250<<10, 2*time.Millisecond)
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, l.URL, []byte(fedtest.Secret)); err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for i := 1; i <= 30000; i++ {
		want.WriteString(strconv.Itoa(i) + "\n")
	}
	for range 5 {
		if res := run(t, keys, "seq 1 30000", "", nil); res.code == 0 && res.err == nil && res.out != want.String() {
			t.Errorf("exit 0 with %d of %d bytes", len(res.out), want.Len())
		} else if res.err != nil || res.code != 0 {
			t.Logf("failed loudly: %d %v", res.code, res.err)
		}
	}
}

// TestRunPTYMarkerForged: on the PTY path the end marker's nonce is in the
// wrapper's argv, so a process on the remote can print the marker early;
// that may cut the output short, never change the status, which comes
// from the authenticated exit frame.
func TestRunPTYMarkerForged(t *testing.T) {
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Skip("no /proc")
	}
	rm := fedtest.StartNoPipe(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	forge := `n=$(tr '\0' '\n' < /proc/$PPID/cmdline | sed -n 4p); printf 'shells-end-%s-0.' "$n"; exit 9`
	if res := run(t, keys, forge, "", nil); res.err != nil || res.code != 9 {
		t.Errorf("a forged end marker = %+v, want 9 from the exit frame", res)
	}
}

// TestExecUnderNohup: a signal ignored when exec starts (nohup's HUP) stays
// ignored: the exec and its remote command go on.
func TestExecUnderNohup(t *testing.T) {
	if keys := os.Getenv("SHELLS_TEST_NOHUP_KEYS"); keys != "" { // the child, under nohup
		os.Exit(federate.Main([]string{"exec", "box", "sleep 1; echo done"}, keys, func(string) (string, error) { return id, nil }))
	}
	nohup, err := exec.LookPath("nohup")
	if err != nil {
		t.Skip("no nohup")
	}
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := exec.Command(nohup, os.Args[0], "-test.run=^TestExecUnderNohup$")
	cmd.Env = append(os.Environ(), "SHELLS_TEST_NOHUP_KEYS="+keys)
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	_ = cmd.Process.Signal(syscall.SIGHUP)
	if err := cmd.Wait(); err != nil || !strings.Contains(out.String(), "done") {
		t.Errorf("exec under nohup after a HUP = %v, %q; want exit 0 and done", err, out.String())
	}
}

func TestSetupWrongSecret(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, "wrong")
	if !errors.Is(err, federate.ErrWrongSecret) {
		t.Fatalf("setup with a wrong secret: %v", err)
	}
	if _, err := os.Stat(filepath.Join(keys, id+".shells")); !os.IsNotExist(err) {
		t.Fatalf("a wrong secret wrote the credential (%v)", err)
	}
}

func TestRunRefusesChangedIdentity(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	rm.Rekey(t)
	if res := run(t, keys, "true", "", nil); res.err == nil || !strings.Contains(res.err.Error(), "identity changed") {
		t.Fatalf("run after an identity change: %+v", res)
	}
}

func TestRunRefusesChangedTLS(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	rm.SwapCert(t)
	if res := run(t, keys, "true", "", nil); res.err == nil || !strings.Contains(res.err.Error(), "TLS certificate changed") {
		t.Fatalf("run after a TLS change: %+v", res)
	}
}

func TestRunSignalDeletesSession(t *testing.T) {
	rm := fedtest.StartNoPipe(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(chan os.Signal, 1)
	go func() {
		for i := 0; i < 500 && rm.Mgr.Count() == 0; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		sigs <- syscall.SIGINT
	}()
	res := run(t, keys, "sleep 30", "", sigs)
	if res.err != nil || res.code != 130 {
		t.Fatalf("run on SIGINT = %+v, want 130", res)
	}
	if n := rm.Mgr.Count(); n != 0 {
		t.Fatalf("SIGINT left %d remote sessions", n)
	}
}

func TestOpenDelete(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var ae *federate.APIError
	if _, _, err := federate.Open(keys, id, 80, 24, filepath.Join(rm.Dir, "nope"), ""); !errors.As(err, &ae) || ae.Code != "cwd_unusable" {
		t.Fatalf("open in a missing cwd: %v", err)
	}
	sid, marker, err := federate.Open(keys, id, 80, 24, rm.Dir, "")
	if err != nil || marker != "" || rm.Mgr.Get(sid) == nil {
		t.Fatalf("open = %q %q %v", sid, marker, err)
	}
	if _, marker, err := federate.Open(keys, id, 80, 24, "", "sleep 30"); err != nil || marker == "" {
		t.Fatalf("open with a command = %q %v, want a gate marker", marker, err)
	}
	federate.Delete(keys, id, sid)
	if rm.Mgr.Get(sid) != nil {
		t.Fatal("Delete left the remote session")
	}
}

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://Shells-X.Relay.union.cat/a/b?c#d": "https://shells-x.relay.union.cat",
		"https://10.0.0.1:8443":                    "https://10.0.0.1:8443",
		"https://host:443":                         "https://host",
		"http://host":                              "",
		"https://user:pw@host":                     "",
		"https://host:99999":                       "",
		"https://-host":                            "",
		"https://[::1]":                            "",
		"host":                                     "",
	} {
		got, _, _, err := federate.NormalizeURL(in)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"../../x", "a/b", "", "0b7a3c52-5d1e-4f6a-9c3b-2e8d7f1a4b6."} {
		if err := federate.Setup(t.TempDir(), bad, "https://127.0.0.1:1", []byte("s")); err == nil || !strings.Contains(err.Error(), "invalid connection id") {
			t.Errorf("Setup with id %q: %v", bad, err)
		}
	}
}

// TestCallReusesClient: picker calls in a burst share one authenticated
// client (no new socket or TLS connection after the first), and a removed
// connection is never served from the pool.
// TestCallPoolDrains: the remote's broadcasts (a session created anywhere)
// reach a pooled client too; unread they would fill its queue and stall it.
func TestCallPoolDrains(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := federate.Call(keys, id, "/api/ls", map[string]any{"path": rm.Dir}); err != nil {
		t.Fatal(err)
	}
	for range 70 {
		s, err := rm.Mgr.Create(80, 24, "", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		rm.Mgr.Destroy(s.ID)
	}
	time.Sleep(300 * time.Millisecond)
	if n := federate.PoolBacklog(id); n != 0 {
		t.Errorf("%d frames left unread in the pooled client", n)
	}
}

// TestCallPoolRace: Calls racing while the pooled socket goes away replace
// the client under the pool's lock (go test -race).
func TestCallPoolRace(t *testing.T) {
	rm := fedtest.Start(t)
	keys, err := setup(t, rm, fedtest.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 6 {
				_, _ = federate.Call(keys, id, "/api/ls", map[string]any{"path": rm.Dir})
				federate.PoolDropSocket(id)
			}
		}()
	}
	wg.Wait()
}

// TestPlainAPIErrorIgnored: a reply that is not encrypted comes from anyone
// on the route (a relay): its body is never taken as the remote's error or
// code, and nothing printed carries control characters.
func TestPlainAPIErrorIgnored(t *testing.T) {
	rm := fedtest.Start(t)
	relay := rm.Relay(t, func(_ bool, p []byte) [][]byte { return [][]byte{p} }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"\u001b]52;c;cHduZWQ=\u0007 log in again","code":"cwd_unusable"}`))
	}))
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, relay, []byte(fedtest.Secret)); err != nil {
		t.Fatal(err)
	}
	_, err := federate.Call(keys, id, "/api/ls", map[string]any{"path": rm.Dir})
	var ae *federate.APIError
	if !errors.As(err, &ae) || ae.Code != "" || strings.ContainsAny(ae.Msg, "\x1b\x07") {
		t.Errorf("plain 401 = %#v", err)
	}
	if got := federate.Printable("a\x1b]0;x\x07b\u009b2Jc\td"); got != "a]0;xb2Jcd" {
		t.Errorf("Printable = %q", got)
	}
}

func TestCallReusesClient(t *testing.T) {
	rm := fedtest.Start(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var dials atomic.Int32
	go func() {
		for {
			a, err := ln.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			b, err := net.Dial("tcp", strings.TrimPrefix(rm.URL, "https://"))
			if err != nil {
				a.Close()
				continue
			}
			go io.Copy(a, b)
			go io.Copy(b, a)
		}
	}()
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, "https://"+ln.Addr().String(), []byte(fedtest.Secret)); err != nil {
		t.Fatal(err)
	}
	ls := func() error {
		_, err := federate.Call(keys, id, "/api/ls", map[string]any{"path": rm.Dir})
		return err
	}
	if err := ls(); err != nil {
		t.Fatal(err)
	}
	n := dials.Load()
	for range 3 {
		if err := ls(); err != nil {
			t.Fatal(err)
		}
	}
	if d := dials.Load() - n; d != 0 {
		t.Errorf("%d new connections for pooled calls", d)
	}
	if err := os.Remove(filepath.Join(keys, id+".shells")); err != nil {
		t.Fatal(err)
	}
	if err := ls(); err == nil {
		t.Error("a removed connection was served from the pool")
	}
}
