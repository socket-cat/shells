// SPDX-License-Identifier: AGPL-3.0-or-later
// Shells — socket.cat. Author: Carles Ortega Ragull <ragull@socket.cat>
//
// Wire-protocol v3: P-256 ECDH + HKDF-SHA256 + AES-256-GCM + HMAC-SHA256.
// Pure Go standard library; no third-party modules.

// Package main is the shells server entrypoint.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"shells/internal/api"
	"shells/internal/auth"
	"shells/internal/binpath"
	"shells/internal/branding"
	"shells/internal/config"
	"shells/internal/crypto"
	"shells/internal/release"
	"shells/internal/selftls"
	"shells/internal/selfupdate"
	"shells/internal/session"
	"shells/internal/ssh"
	"shells/internal/static"
	"shells/internal/wshandler"
)

//go:generate go run scripts/gzassets.go

// publicgz is public/ pre-gzipped by scripts/gzassets.go; static.Unpack
// inflates it into memory at startup.
//
//go:embed publicgz
var embedPublic embed.FS

//go:embed VERSION
var embedVersion []byte

func main() {
	// Self-update by default: the binary runs a child copy of itself so it can
	// apply its own verified updates (preflight, swap, rollback).
	if selfupdate.Enabled() {
		selfupdate.Run() // the parent owns the process from here on
		os.Exit(0)       // safety net: never fall through to the server code
	}

	version := strings.TrimSpace(string(embedVersion))

	cfg, err := config.Load(version)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if err := release.Init(); err != nil {
		log.Fatalf("release: %v", err)
	}

	mgr, err := session.New(cfg)
	if err != nil {
		log.Fatalf("session manager: %v", err)
	}

	authStore := auth.NewStore(cfg.AppToken)

	// Periodic token cleanup.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		for range t.C {
			authStore.Cleanup()
		}
	}()

	// Initialise binary cache for /api/which tab-completion.
	binpath.Init()

	// Initialise SSH manager and wire into session manager.
	sshMgr := ssh.NewManager(cfg)
	if cfg.SSHAvailable {
		mgr.SpawnSSH = ssh.Spawn(cfg)
		mgr.SSHValidate = sshMgr.Validate()
	}

	wsH := wshandler.New(cfg, mgr, authStore)
	wsH.RegisterSessionEvents()

	subFS, err := fs.Sub(embedPublic, "publicgz")
	if err == nil {
		subFS, err = static.Unpack(subFS)
	}
	if err != nil {
		log.Fatalf("embed assets: %v", err)
	}

	brand := branding.Load(cfg.BrandingFile, cfg.AppName, cfg.Accent)

	// SHELLS_DEV_TAG (dev deploys only) busts ?v= + the SW cache per build; unset in production
	staticH, err := static.New(subFS, version+os.Getenv("SHELLS_DEV_TAG"), cfg.ServerKeyDir, cfg.Accent, cfg.AppName, brand)
	if err != nil {
		log.Fatalf("static: %v", err)
	}

	apiH := api.New(cfg, mgr, authStore, sshMgr, brand)

	mux := http.NewServeMux()
	mux.Handle("/ws", wsH)
	mux.HandleFunc("/api/", apiH.ServeHTTP)
	mux.Handle("/", staticH)

	addr := cfg.Addr()
	scheme := "http"
	var certFile, keyFile string
	if cfg.TLS {
		scheme = "https"
		certFile, keyFile, err = selftls.Load(cfg.ServerKeyDir)
		if err != nil {
			log.Fatalf("selftls: %v", err)
		}
	}
	var note string
	if n := tokenLogNote(cfg.TokenSource); n != "" {
		note = " " + n
	}
	log.Printf("Shells v%s listening on %s://%s%s", version, scheme, addr, note)
	log.Printf("State dir: %s", cfg.ServerKeyDir)
	switch cfg.SecretSource {
	case "generated":
		log.Printf(`
================================================================================
 E2E secret (auto-generated on first launch — required to sign in to the app):

   %s

 Saved to %s — edit that file to change it.
================================================================================`, cfg.Secret, cfg.SecretFile)
	case "file":
		log.Printf("E2E secret: (loaded from %s — edit that file to change it)", cfg.SecretFile)
	case "$SHELLS_SECRET", "$SECRET":
		log.Printf("E2E secret: (from %s env; to persist instead, write it to %s)", cfg.SecretSource, cfg.SecretFile)
	case "env":
		log.Printf("E2E secret: (from $SHELLS_SECRET env; to persist instead, write it to %s)", cfg.SecretFile)
	default:
		log.Printf("E2E secret: (from %s; secret file: %s)", cfg.SecretSource, cfg.SecretFile)
	}

	cors := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if origin := r.Header.Get("Origin"); origin != "" {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Allow-Credentials", "true")
			}
			// Short-circuit CORS preflight: must NOT require auth.
			if r.Method == http.MethodOptions {
				h := w.Header()
				h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, X-Shells-Encrypted, X-Shells-Token")
				h.Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	securityHeaders := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			// HSTS is intentionally not set here: TLS is normally terminated by
			// the reverse proxy, which owns the HSTS header. The app's plain
			// listener (the common proxy mode) never sends it.
			next.ServeHTTP(w, r)
		})
	}

	recovery := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("panic recovered: %v\n%s", rec, debug.Stack())
					// 200 with error body: nginx can't intercept a 200.
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"error":"Internal error (recovered)"}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}

	// TLS hardening toward SSL Labs A+: minimum TLS 1.2, and an explicit
	// strong-only TLS 1.2 cipher set (ECDHE-ECDSA with AEAD). TLS 1.3 suites
	// and forward secrecy curves are Go defaults. The cert is ECDSA
	// (selftls uses P-256), so ECDSA suites only.
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           securityHeaders(cors(recovery(mux))),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second, // headers only; does not cap long-lived WS
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(dropHandshakeEOF{log.Writer()}, "", log.Flags()),
	}
	// HTTP/1.1 only: scripts/build.sh omits net/http's HTTP/2 (nethttpomithttp2),
	// but Go would still advertise "h2" via ALPN and browsers would fail.
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)

	// Graceful shutdown.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		mgr.DestroyAll()
		crypto.Shutdown()
	}()

	var serveErr error
	if cfg.TLS {
		serveErr = server.ListenAndServeTLS(certFile, keyFile)
	} else {
		serveErr = server.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		if errors.Is(serveErr, syscall.EADDRINUSE) {
			log.Printf("port %d already in use — another instance is running", cfg.Port)
			os.Exit(selfupdate.PortBusyCode) // supervisor stops cleanly, no crash-loop
		}
		log.Fatalf("server: %v", serveErr)
	}
}

// dropHandshakeEOF drops net/http's "TLS handshake error ...: EOF" lines: a
// liveness probe (TCP connect + close, e.g. the socket.cat relay) logs one per
// check forever. Real handshake failures (bad cert, protocol) still pass.
type dropHandshakeEOF struct{ w io.Writer }

func (d dropHandshakeEOF) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) && bytes.HasSuffix(bytes.TrimSpace(p), []byte(": EOF")) {
		return len(p), nil
	}
	return d.w.Write(p)
}

// tokenLogNote describes where the app auth token came from WITHOUT printing
// any substring of it: tokens are bearer credentials and startup logs are
// routinely shipped to remote aggregation, so only the source is named.
// When auto-generated (the default), no note is printed to avoid confusing
// operators who authenticate via E2E secret.
func tokenLogNote(source string) string {
	switch source {
	case "env":
		return "(auth token from $SHELLS_TOKEN)"
	default:
		return ""
	}
}
