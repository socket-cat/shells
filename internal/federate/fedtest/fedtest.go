// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package fedtest starts a real shells remote for tests of internal/federate
// and its callers: the production /ws and /api handlers on an httptest TLS
// listener with a self-signed certificate (the blind route). Tests only; the
// binary never imports it.
package fedtest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"shells/internal/api"
	"shells/internal/auth"
	"shells/internal/binpath"
	"shells/internal/branding"
	"shells/internal/config"
	"shells/internal/crypto"
	"shells/internal/selftls"
	"shells/internal/session"
	"shells/internal/ssh"
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
	cert atomic.Pointer[tls.Certificate]
}

// Start runs a remote until the test ends, CheckOrigin on.
func Start(t *testing.T) *Remote {
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
	apiH := api.New(cfg, rm.Mgr, authStore, ssh.NewManager(cfg), branding.Load(cfg.BrandingFile, "Shells", "#fab283"))
	mux := http.NewServeMux()
	mux.Handle("/ws", wsH)
	mux.HandleFunc("/api/", apiH.ServeHTTP)

	rm.SwapCert(t)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: []tls.Certificate{*rm.cert.Load()}, NextProtos: []string{"http/1.1"}}, nil
	}}
	srv.StartTLS()
	t.Cleanup(func() { srv.Close(); rm.Mgr.DestroyAll() })
	rm.URL = srv.URL
	return rm
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
