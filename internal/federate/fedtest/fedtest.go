// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package fedtest starts a real shells remote for tests of internal/federate
// and its callers: the production /ws and /api handlers on an httptest TLS
// listener with a self-signed certificate (the blind route). Tests only; the
// binary never imports it.
package fedtest

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shells/internal/api"
	"shells/internal/auth"
	"shells/internal/binpath"
	"shells/internal/branding"
	"shells/internal/config"
	"shells/internal/crypto"
	"shells/internal/selftls"
	"shells/internal/session"
	"shells/internal/ssh"
	"shells/internal/websocket"
	"shells/internal/wshandler"
)

// Secret is the remote's E2E secret; Salt its salt.
const Secret = "holahola"

var Salt = []byte("0123456789abcdef")

var binpathOnce sync.Once

// Remote is a running shells remote. Its crypto identity is the package-level
// server half, so one Remote per test at a time.
type Remote struct {
	URL  string
	Dir  string
	Mgr  *session.Manager
	WS   *wshandler.Handler
	cert atomic.Pointer[tls.Certificate]
	// GUC, when set, gates every request on that GUC cookie with a 401, as
	// the socket.cat relay does.
	GUC atomic.Pointer[string]
}

// Start runs a remote until the test ends, CheckOrigin on.
func Start(t *testing.T) *Remote { t.Helper(); return start(t, false) }

// StartNoPipe runs a remote from before pipe mode: no caps, exec in a PTY.
func StartNoPipe(t *testing.T) *Remote { t.Helper(); return start(t, true) }

func start(t *testing.T, noPipe bool) *Remote {
	t.Helper()
	rm := &Remote{Dir: t.TempDir()}
	binpathOnce.Do(binpath.Init) // the command index /api/which answers from
	if err := crypto.Init([]byte(Secret), Salt, filepath.Join(rm.Dir, "server-key")); err != nil {
		t.Fatal(err)
	}
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		KeepaliveIntervalMs: config.KeepaliveIntervalMs, MaxSessions: 4, MaxClientsPerSession: config.MaxClientsPerSession,
		OutputBufferMax: config.OutputBufferMax, WSHWM: config.WSHWM, WSLWM: config.WSLWM, WSCWM: config.WSCWM,
		NonReplayableDecModes: config.NonReplayableDecModes, ShellEnvKeys: config.ShellEnvKeys,
		DefaultShell: shell, Cwd: rm.Dir, CheckOrigin: true, ServerKeyDir: rm.Dir,
		BrandingFile: filepath.Join(rm.Dir, "branding.json"), SSHConnectionsFile: filepath.Join(rm.Dir, "ssh.json"),
	}
	if rm.Mgr, err = session.New(cfg); err != nil {
		t.Fatal(err)
	}
	authStore := auth.NewStore("")
	wsH := wshandler.New(cfg, rm.Mgr, authStore)
	wsH.RegisterSessionEvents()
	wsH.NoPipe = noPipe
	rm.WS = wsH
	apiH := api.New(cfg, rm.Mgr, authStore, ssh.NewManager(cfg), branding.Load(cfg.BrandingFile, "Shells", "#fab283"))
	mux := http.NewServeMux()
	mux.Handle("/ws", wsH)
	mux.HandleFunc("/api/", apiH.ServeHTTP)

	rm.SwapCert(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g := rm.GUC.Load(); g != nil {
			if c, err := r.Cookie("GUC"); err != nil || c.Value != *g {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(w, r)
	}))
	// The production listener (main.go): TLS and plain http on one port.
	srv.Listener = selftls.Dual(smallSendBuf{srv.Listener}, &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: []tls.Certificate{*rm.cert.Load()}, NextProtos: []string{"http/1.1"}}, nil
	}})
	srv.Start()
	t.Cleanup(func() { srv.Close(); rm.Mgr.DestroyAll() })
	rm.URL = "https" + strings.TrimPrefix(srv.URL, "http")
	return rm
}

// Roots is a pool holding the certificate served now, as if a public CA
// vouched for it.
func (rm *Remote) Roots(t *testing.T) *x509.CertPool {
	t.Helper()
	leaf, err := x509.ParseCertificate(rm.cert.Load().Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool
}

// SwapCert serves a fresh self-signed certificate from now on.
func (rm *Remote) SwapCert(t *testing.T) {
	t.Helper()
	certFile, keyFile, err := selftls.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	rm.cert.Store(&cert)
}

// Rekey gives the remote a new identity key, same secret and salt: what a
// MITM holding the secret, or a remote whose key dir was reset, looks like.
func (rm *Remote) Rekey(t *testing.T) {
	t.Helper()
	if err := crypto.Init([]byte(Secret), Salt, filepath.Join(t.TempDir(), "server-key")); err != nil {
		t.Fatal(err)
	}
}

// smallSendBuf fixes accepted connections' send buffer at 32 KB (no kernel
// autotuning to MBs): behind a slow Link the queue builds in the remote's
// WebSocket layer, where pipe mode's flow control acts.
type smallSendBuf struct{ net.Listener }

func (l smallSendBuf) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetWriteBuffer(32 << 10)
	}
	return c, err
}

// Link is a TCP proxy to a remote shaped like a slow link: rate bytes per
// second and delay each way. With the remote's small send buffer
// (smallSendBuf) the queue builds in its WebSocket layer, as behind a real
// bottleneck.
type Link struct {
	URL   string
	rate  int
	delay time.Duration
	stall atomic.Int64 // unix nanos: nothing moves before
	mu    sync.Mutex
	conns []net.Conn
}

// Link starts a proxy to rm until the test ends; rate 0 is unthrottled.
func (rm *Remote) Link(t *testing.T, rate int, delay time.Duration) *Link {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &Link{URL: "https://" + ln.Addr().String(), rate: rate, delay: delay}
	t.Cleanup(func() { ln.Close(); l.Cut() })
	go func() {
		for {
			a, err := ln.Accept()
			if err != nil {
				return
			}
			b, err := net.Dial("tcp", strings.TrimPrefix(rm.URL, "https://"))
			if err != nil {
				a.Close()
				continue
			}
			l.mu.Lock()
			l.conns = append(l.conns, a, b)
			l.mu.Unlock()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); l.pipe(a, b) }()
			go func() { defer wg.Done(); l.pipe(b, a) }()
			go func() { wg.Wait(); a.Close(); b.Close() }()
		}
	}()
	return l
}

// Stall stops the link for d.
func (l *Link) Stall(d time.Duration) { l.stall.Store(time.Now().Add(d).UnixNano()) }

// Cut drops every connection through the link, with no close frame.
func (l *Link) Cut() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		c.Close()
	}
}

// pipe moves src to dst: paced at rate, each chunk delay after it was sent.
// src's EOF goes on as dst's (a half-close, as a TCP relay passes a FIN on);
// a failed write aborts both.
func (l *Link) pipe(dst, src net.Conn) {
	type chunk struct {
		b  []byte
		at time.Time
	}
	ch := make(chan chunk, 16)
	go func() {
		defer close(ch)
		for {
			b := make([]byte, 1024)
			n, err := src.Read(b)
			if n > 0 {
				ch <- chunk{b[:n], time.Now()}
			}
			if err != nil {
				return
			}
		}
	}()
	free := time.Now() // the link has sent everything before c; from timestamps, so a late wakeup costs no rate
	for c := range ch {
		if st := time.Unix(0, l.stall.Load()); free.Before(st) {
			free = st
		}
		if free.Before(c.at) {
			free = c.at
		}
		if l.rate > 0 {
			free = free.Add(time.Duration(len(c.b)) * time.Second / time.Duration(l.rate))
		}
		time.Sleep(time.Until(free.Add(l.delay)))
		if _, err := dst.Write(c.b); err != nil {
			dst.Close()
			src.Close()
			for range ch {
			}
			return
		}
	}
	_ = dst.(*net.TCPConn).CloseWrite()
}

// Relay is a WebSocket relay to rm that terminates TLS, as socket.cat's
// vhosts do: it sees every frame outside TLS (still E2E-encrypted, [type] ||
// ciphertext) and tamper decides what goes on for binary ones, up from the
// client: none drops it, two replay it, holding one back reorders. Each
// direction calls tamper from its own goroutine. api, if set, answers
// everything but /ws, as the relay's own pages would. Its URL serves a
// certificate of its own.
func (rm *Remote) Relay(t *testing.T, tamper func(up bool, p []byte) [][]byte, api http.Handler) string {
	t.Helper()
	var up websocket.Upgrader
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			if api != nil {
				api.ServeHTTP(w, r)
			}
			return
		}
		u, _ := url.Parse(rm.URL)
		conn, err := tls.Dial("tcp", u.Host, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		remote, err := websocket.Client(conn, &url.URL{Scheme: "wss", Host: u.Host, Path: "/ws"}, http.Header{})
		if err != nil {
			conn.Close()
			return
		}
		client, err := up.Upgrade(w, r)
		if err != nil {
			remote.Close(1000, "")
			return
		}
		pass := func(dir bool, to *websocket.Conn) func([]byte, bool) {
			return func(p []byte, binary bool) {
				if !binary {
					to.SendText(p)
					return
				}
				for _, q := range tamper(dir, p) {
					to.SendBinary(q)
				}
			}
		}
		client.OnMessage, remote.OnMessage = pass(true, remote), pass(false, client)
		client.OnClose = func(int, string) { remote.Close(1000, "") }
		remote.OnClose = func(int, string) { client.Close(1000, "") }
		go remote.Start()
		client.Start()
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
