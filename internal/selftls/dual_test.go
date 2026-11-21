// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package selftls

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type connKey struct{}

// One port answers https and plain http, and survives a silent or garbage peer.
func TestDual(t *testing.T) {
	cert, key, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	type halfCloser interface{ CloseWrite() error }
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The websocket layer half-closes through these interfaces.
		c := r.Context().Value(connKey{}).(net.Conn)
		if tc, ok := c.(*tls.Conn); ok {
			c = tc.NetConn()
		}
		if _, ok := c.(halfCloser); !ok {
			t.Errorf("conn %T has no CloseWrite", c)
		}
		if r.TLS != nil {
			io.WriteString(w, "tls")
		} else {
			io.WriteString(w, "plain")
		}
	}))
	srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connKey{}, c)
	}
	srv.Listener = Dual(srv.Listener, &tls.Config{Certificates: []tls.Certificate{pair}})
	srv.Start()
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	silent, _ := net.Dial("tcp", host) // never sends: must not stall the others
	defer silent.Close()
	garbage, _ := net.Dial("tcp", host)
	garbage.Write([]byte("\x00\x01garbage"))
	defer garbage.Close()

	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	for scheme, want := range map[string]string{"http": "plain", "https": "tls"} {
		res, err := insecure.Get(scheme + "://" + host + "/")
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if string(body) != want {
			t.Errorf("%s: got %q, want %q", scheme, body, want)
		}
	}
}
