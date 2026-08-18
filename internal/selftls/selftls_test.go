// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package selftls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestLoadGeneratesSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(certFile); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	fi, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", fi.Mode().Perm())
	}

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("generated pair does not load: %v", err)
	}

	raw, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.IsCA {
		t.Error("leaf cert must not be a CA")
	}
	if !hasExtKeyUsage(cert, x509.ExtKeyUsageServerAuth) {
		t.Errorf("ExtKeyUsage %v missing ServerAuth", cert.ExtKeyUsage)
	}
	if !hasString(cert.DNSNames, "localhost") {
		t.Errorf("DNSNames %v missing localhost", cert.DNSNames)
	}
	if !hasIP(cert.IPAddresses, "127.0.0.1") {
		t.Errorf("IPAddresses %v missing 127.0.0.1", cert.IPAddresses)
	}
	if !hasIP(cert.IPAddresses, "::1") {
		t.Errorf("IPAddresses %v missing ::1", cert.IPAddresses)
	}
}

func TestLoadStableAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	certFile, _, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(dir); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("second Load regenerated the certificate; expected identical bytes")
	}
}

func TestLoadRegeneratesCorruptPair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(dir); err != nil {
		t.Fatalf("Load after corruption: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("regenerated pair does not load: %v", err)
	}
}

func TestLoadServesTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}),
	}
	go func() { _ = server.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	pool := x509.NewCertPool()
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(pemData) {
		t.Fatal("generated cert did not add to pool")
	}
	// RootCAs only — deliberately no InsecureSkipVerify: the client must
	// validate the chain against the generated self-signed cert.
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("GET over TLS: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("GET / = %d %q, want 200 ok", resp.StatusCode, body)
	}
}

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, u := range cert.ExtKeyUsage {
		if u == want {
			return true
		}
	}
	return false
}

func hasString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func hasIP(hay []net.IP, needle string) bool {
	want := net.ParseIP(needle)
	for _, ip := range hay {
		if ip.Equal(want) {
			return true
		}
	}
	return false
}
