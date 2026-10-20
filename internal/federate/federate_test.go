// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	code int
	out  string
	err  error
}

func run(t *testing.T, keys, cmd, stdin string, sigs chan os.Signal) result {
	t.Helper()
	done := make(chan result, 1)
	go func() {
		var out bytes.Buffer
		code, err := federate.Run(keys, id, cmd, strings.NewReader(stdin), &out, sigs)
		done <- result{code, out.String(), err}
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
		cmd, stdin, out string
		code            int
	}{
		{"echo hi; exit 3", "", "hi\n", 3},
		{"echo a; sleep 0.001; echo b", "", "a\nb\n", 0}, // b is flushed after the exit frame
		{"cat", "a\nb", "a\nb", 0},                       // stdin sent, then ^D; not echoed back
		{"echo out; echo err >&2", "", "out\nerr\n", 0},  // merged streams
		{`echo 'it''s' "a'b"`, "", "its a'b\n", 0},       // quotes survive the eval quoting
		{"kill -9 $$", "", "", 137},                      // a signal is 128+n
	} {
		res := run(t, keys, tc.cmd, tc.stdin, nil)
		if res.err != nil || res.code != tc.code || res.out != tc.out {
			t.Errorf("run %q = %d %q %v, want %d %q", tc.cmd, res.code, res.out, res.err, tc.code, tc.out)
		}
	}
	// A command the remote shell cannot parse fails after the gate (eval):
	// its error and status come back.
	if res := run(t, keys, "echo 'unterminated", "", nil); res.err != nil || res.code == 0 || !strings.Contains(res.out, "nterminated") {
		t.Errorf("syntax error = %d %q %v", res.code, res.out, res.err)
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
	rm := fedtest.Start(t)
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
