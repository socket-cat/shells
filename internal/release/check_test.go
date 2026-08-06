// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package release

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeReleaseServer serves a signed release manifest + binary, like GitHub +
// socket.cat do in production. It signs with a throwaway key so the test never
// touches the real pinned private keys.
func fakeReleaseServer(t *testing.T, tag string) (string, string, []byte, *httptest.Server, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fp := FingerprintOf(pub)

	binary := []byte("#!/bin/sh\necho fake-binary\n")
	sum := sha256.Sum256(binary)
	manifest := fmt.Sprintf("# shells %s\n%s  shells-linux-amd64\n", tag, hex.EncodeToString(sum[:]))
	sig := ed25519.Sign(priv, []byte(manifest))

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/x/y/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name": "v%s"}`, tag)
	})
	mux.HandleFunc("/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(manifest))
	})
	mux.HandleFunc("/checksums.txt.sig", func(w http.ResponseWriter, r *http.Request) {
		w.Write(sig)
	})
	mux.HandleFunc("/shells-linux-amd64", func(w http.ResponseWriter, r *http.Request) {
		w.Write(binary)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	base := srv.URL
	return base, fp, binary, srv, pub
}

// useTestKey swaps the pinned keys for a throwaway key for the duration of the
// test, so the verify() path can be exercised without the real keys.
func useTestKey(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	old := pinnedKeys
	pinnedKeys = []pinnedKey{{fingerprint: FingerprintOf(pub), pub: pub}}
	t.Cleanup(func() { pinnedKeys = old })
}

func testConfig(base, fp, binaryPath string) Config {
	return Config{
		Version:      "1.0.1",
		Repo:         "x/y",
		APIBase:      base,
		SigURL:       base + "/checksums.txt.sig",
		ChecksumsURL: base + "/checksums.txt",
		DownloadBase: base + "/",
		Platform:     "shells-linux-amd64",
		UserAgent:    "shells/test",
		UpdateCheck:  true,
		BinaryPath:   binaryPath,
	}
}

func TestCheckLatestEndToEnd(t *testing.T) {
	base, fp, _, _, pub := fakeReleaseServer(t, "2.0.0")
	useTestKey(t, pub)

	binPath := filepath.Join(t.TempDir(), "shells")
	info := CheckLatest(context.Background(), testConfig(base, fp, binPath))

	if !info.UpdateAvailable {
		t.Fatalf("expected update available, got %+v", info)
	}
	if info.LatestVersion != "2.0.0" {
		t.Errorf("latest = %q, want 2.0.0", info.LatestVersion)
	}
	if !info.ChecksumVerified || !info.SignatureVerified {
		t.Errorf("verification flags missing: %+v", info)
	}
	if info.SignedBy != fp {
		t.Errorf("signedBy = %q, want %q", info.SignedBy, fp)
	}
}

func TestCheckLatestNoUpdateSkipsSig(t *testing.T) {
	// Sig endpoint returns 500: if the flow wrongly fetches it when no update
	// exists, the check would fail instead of returning "no update".
	base, _, _, _, _ := fakeReleaseServer(t, "1.0.0")
	cfg := testConfig(base, "", filepath.Join(t.TempDir(), "shells"))
	cfg.SigURL = base + "/missing.sig" // not served -> 404

	info := CheckLatest(context.Background(), cfg)
	if info.UpdateAvailable {
		t.Fatalf("no update expected for older tag, got %+v", info)
	}
	if info.Error != "" {
		t.Errorf("expected clean no-update, got error %q", info.Error)
	}
}

func TestCheckLatestSignatureMismatchAlarms(t *testing.T) {
	// A socket.cat signature that does not verify over GitHub's checksums must
	// surface as VerificationFailed (supply-chain alarm), NOT as a neutral
	// "update check failed".
	base, _, _, _, pub := fakeReleaseServer(t, "2.0.0")
	useTestKey(t, pub)

	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, ed25519.SignatureSize)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		w.Write(b)
	}))
	t.Cleanup(garbage.Close)

	cfg := testConfig(base, "", filepath.Join(t.TempDir(), "shells"))
	cfg.SigURL = garbage.URL + "/bad.sig" // loopback http allowed for tests

	info := CheckLatest(context.Background(), cfg)
	if !info.VerificationFailed {
		t.Fatalf("expected verificationFailed alarm, got %+v", info)
	}
	if info.Error == "" {
		t.Error("expected a verification-failure error message")
	}
	if info.UpdateAvailable {
		t.Error("update must not be advertised when verification failed")
	}
}

func TestApplyDownloadsVerifiedBinary(t *testing.T) {
	base, _, wantBinary, _, pub := fakeReleaseServer(t, "2.0.0")
	useTestKey(t, pub)
	binPath := filepath.Join(t.TempDir(), "shells")

	ver, err := Apply(context.Background(), testConfig(base, "", binPath))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if ver != "2.0.0" {
		t.Errorf("version = %q, want 2.0.0", ver)
	}
	got, err := os.ReadFile(binPath + ".new")
	if err != nil {
		t.Fatalf("read staged binary: %v", err)
	}
	if string(got) != string(wantBinary) {
		t.Errorf("staged binary mismatch")
	}
	if !strings.HasPrefix(string(got), "#!/bin/sh") {
		t.Errorf("staged binary does not look executable")
	}
}

func TestApplyRejectsTamperedBinary(t *testing.T) {
	base, _, _, _, pub := fakeReleaseServer(t, "2.0.0")
	useTestKey(t, pub)
	// Serve a corrupted binary (differs from the digest the manifest signs for)
	// and point DownloadBase at it — the sha256 check must fail.
	tamper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tampered"))
	}))
	t.Cleanup(tamper.Close)

	cfg := testConfig(base, "", filepath.Join(t.TempDir(), "shells"))
	cfg.DownloadBase = tamper.URL + "/"

	if _, err := Apply(context.Background(), cfg); err == nil {
		t.Fatalf("expected sha256 mismatch error, got nil")
	}
}
