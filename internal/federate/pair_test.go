// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"shells/internal/federate"
	"shells/internal/federate/fedtest"
)

// socketCat stubs guc's start.php ?pair / ?check / ?unpair.
type socketCat struct {
	sync.Mutex
	origins  []string
	approved bool
	sid      string
	unpaired []string
}

const (
	device = "dddddddddddddddddddddddddddddddd"
	sid    = "ssssssssssssssssssssssssssssssss"
	sid2   = "tttttttttttttttttttttttttttttttt"
)

func (s *socketCat) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Lock()
	defer s.Unlock()
	q := r.URL.Query()
	switch {
	case q.Has("pair"):
		s.origins = append(s.origins, q.Get("pair"))
		w.Write([]byte("ABCD-EFGH " + device))
	case q.Has("check") && r.Header.Get("SOCAT") == device:
		if s.approved {
			w.Write([]byte(s.sid))
		} else {
			w.Write([]byte("wait"))
		}
	case q.Has("unpair"):
		s.unpaired = append(s.unpaired, r.Header.Get("SOCAT"))
	default:
		w.Write([]byte("gone"))
	}
}

func TestPairing(t *testing.T) {
	rm := fedtest.Start(t)
	g := sid
	rm.GUC.Store(&g)
	sc := &socketCat{sid: sid}
	stub := httptest.NewServer(sc)
	defer stub.Close()
	defer federate.SetPairing(stub.URL, "127.0.0.1", rm.Roots(t))()

	var pe *federate.PairError
	for range 2 {
		if err := federate.Probe(rm.URL + "/x"); !errors.As(err, &pe) || pe.Code != "ABCD-EFGH" || pe.URL != stub.URL+"/start.php?code=ABCD-EFGH" {
			t.Fatalf("probe before approval: %v", err)
		}
	}
	if len(sc.origins) != 1 || sc.origins[0] != rm.URL {
		t.Fatalf("one code per pending pairing, for the origin: %q", sc.origins)
	}

	sc.approved = true
	if err := federate.Probe(rm.URL); err != nil {
		t.Fatalf("probe after approval: %v", err)
	}
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, rm.URL, []byte(fedtest.Secret)); err != nil {
		t.Fatalf("setup: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(keys, id+".shells"))
	if !strings.Contains(string(raw), `"guc": "`+sid+`"`) {
		t.Fatalf("credential lacks the relay session: %s", raw)
	}
	if r := run(t, keys, "echo hi", "", nil); r.err != nil || r.code != 0 || r.out != "hi\n" {
		t.Fatalf("run through the gate: %+v", r)
	}

	g2 := sid2
	rm.GUC.Store(&g2)
	if r := run(t, keys, "true", "", nil); r.err == nil || !strings.Contains(r.err.Error(), "refused this server's pairing") {
		t.Fatalf("revoked session: %+v", r)
	}
	sc.sid = sid2
	if err := federate.Probe(rm.URL); !errors.As(err, &pe) || len(sc.origins) != 2 {
		t.Fatalf("probe after setup pairs again: %v, %d codes", err, len(sc.origins))
	}
	if err := federate.Setup(keys, id, rm.URL, []byte(fedtest.Secret)); err != nil {
		t.Fatalf("re-setup: %v", err)
	}
	if len(sc.unpaired) != 1 || sc.unpaired[0] != sid {
		t.Fatalf("re-pairing must revoke the session it replaces: %q", sc.unpaired)
	}
	if r := run(t, keys, "echo hi", "", nil); r.err != nil || r.out != "hi\n" {
		t.Fatalf("run after re-pairing: %+v", r)
	}

	federate.Unpair(keys, id)
	if len(sc.unpaired) != 2 || sc.unpaired[1] != sid2 {
		t.Fatalf("unpair sent %q", sc.unpaired)
	}
}

// TestPairingNeverOnFirstUse: an approved GUC goes only to a certificate the
// roots vouch for; a self-signed one (a MITM) gets the TLS refusal, no cookie.
func TestPairingNeverOnFirstUse(t *testing.T) {
	rm := fedtest.Start(t)
	var mu sync.Mutex
	var seen []string
	mitm := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Values("Cookie")...)
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer mitm.Close()
	stub := httptest.NewServer(&socketCat{sid: sid, approved: true})
	defer stub.Close()
	defer federate.SetPairing(stub.URL, "127.0.0.1", rm.Roots(t))()

	var pe *federate.PairError
	if err := federate.Probe(mitm.URL); !errors.As(err, &pe) {
		t.Fatalf("first probe mints a code: %v", err)
	}
	if err := federate.Probe(mitm.URL); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("approved probe to a self-signed peer: %v", err)
	}
	keys := filepath.Join(rm.Dir, "ssh-keys")
	if err := federate.Setup(keys, id, mitm.URL, []byte(fedtest.Secret)); err == nil {
		t.Fatal("setup against a self-signed peer succeeded")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatalf("the MITM received %q", seen)
	}
}
