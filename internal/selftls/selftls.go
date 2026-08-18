// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package selftls provides an opt-in self-signed TLS certificate for the
// shells server (SHELLS_TLS=on). The pair is generated once, persisted in the
// key directory, and reused unchanged across restarts.
package selftls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// File names of the persisted certificate pair within the key directory.
const (
	certName = "tls.pem"
	keyName  = "tls-key.pem"
)

// Load returns the paths of a self-signed TLS certificate/key pair stored in
// keyDir. When both files already exist and form a loadable pair they are
// returned as-is (stable across restarts); otherwise a fresh ECDSA P-256
// certificate is generated, written, and returned.
func Load(keyDir string) (certFile, keyFile string, err error) {
	certFile = filepath.Join(keyDir, certName)
	keyFile = filepath.Join(keyDir, keyName)

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		// Re-assert the key mode (mirrors config.ensureDirMode's drift
		// re-assertion): guards restored backups / tar-without-perms drift.
		_ = os.Chmod(keyFile, 0o600)
		return certFile, keyFile, nil
	}

	log.Printf("[selftls] no loadable certificate pair found — generating new self-signed cert in %s", keyDir)

	// A lone half of a previous pair (e.g. a crash between the two writes)
	// would mix generations — drop it so we always regenerate a matched pair.
	if _, err := os.Stat(certFile); err != nil {
		_ = os.Remove(keyFile)
	}
	if _, err := os.Stat(keyFile); err != nil {
		_ = os.Remove(certFile)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "shells"
	}

	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return "", "", fmt.Errorf("serial: %w", err)
	}
	serialBytes[0] &= 0x7f // keep the serial positive

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    now.Add(-time.Hour), // clock skew allowance
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Self-signed leaf only — no CA/leaf split.
		BasicConstraintsValid: true,
		DNSNames:              dedupStrings([]string{"localhost", hostname, hostname + ".local"}),
		IPAddresses:           usableIPs(),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Key first, cert second: a crash in between leaves an invalid pair that
	// fails LoadX509KeyPair and regenerates on the next boot.
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write cert: %w", err)
	}

	return certFile, keyFile, nil
}

// usableIPs returns the loopback addresses (127.0.0.1, ::1) plus every address
// of an up, non-loopback interface, deduplicated. Per-interface failures are
// tolerated — this is best effort.
func usableIPs() []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue // loopback is already covered by 127.0.0.1/::1
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			s := a.String()
			if i := strings.IndexByte(s, '%'); i >= 0 {
				s = s[:i] // strip zone — net.ParseIP cannot handle it
			}
			if ip := net.ParseIP(s); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return dedupIPs(ips)
}

func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func dedupIPs(in []net.IP) []net.IP {
	seen := make(map[string]bool, len(in))
	out := make([]net.IP, 0, len(in))
	for _, ip := range in {
		k := ip.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ip)
	}
	return out
}
