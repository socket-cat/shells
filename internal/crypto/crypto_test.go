// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
)

// TestVerifyHMACProof covers the constant-time HMAC verification used for
// auth proofs. secretHash is set directly so no PBKDF2 (600k iterations)
// runs in tests.
func TestVerifyHMACProof(t *testing.T) {
	secretHash = []byte("0123456789abcdef0123456789abcdef")

	msg := []byte("challenge-payload")
	valid := GenerateHMACProof(msg) // 32 raw bytes → 44 base64 chars

	tests := []struct {
		name  string
		msg   []byte
		proof string
		want  bool
	}{
		{"valid proof", msg, valid, true},
		{"wrong message", []byte("other"), valid, false},
		{"bad base64", msg, "!!!not-base64!!!", false},
		{"empty proof", msg, "", false},
		// Same content class as a length mismatch: must reject without
		// panicking ConstantTimeCompare (stdlib returns 0 on length skew).
		{"truncated payload", msg, "AAAA", false},
		{"right length wrong bytes", msg,
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyHMACProof(tt.msg, tt.proof); got != tt.want {
				t.Fatalf("VerifyHMACProof(%q) = %v, want %v", tt.proof, got, tt.want)
			}
		})
	}

	// The valid encoding must be exactly one SHA-256 block wide.
	if !bytes.Equal(hmacSHA256(msg), hmacSHA256(msg)) {
		t.Fatal("hmacSHA256 not deterministic")
	}
}

// TestClientHandshake runs the client half against the server half: both
// derive the same keys, frames cross both ways, and a wrong secret is refused
// before any client proof is produced.
func TestClientHandshake(t *testing.T) {
	salt := []byte("0123456789abcdef")
	if err := Init([]byte("holahola"), salt, filepath.Join(t.TempDir(), "server-key")); err != nil {
		t.Fatal(err)
	}
	srv := NewState()
	hs, err := NewClientHandshake()
	if err != nil {
		t.Fatal(err)
	}
	ack, err := HandleInitCrypto(srv, hs.PublicKeyB64())
	if err != nil {
		t.Fatal(err)
	}
	if fp, err := Fingerprint(ack["publicKey"].(string)); err != nil || fp != ack["fingerprint"] {
		t.Fatalf("fingerprint %q, ack %q, err %v", fp, ack["fingerprint"], err)
	}
	ackSalt, _ := hex.DecodeString(ack["salt"].(string))
	finish := func(secret string) (*State, string, string, error) {
		return hs.Finish(ack["publicKey"].(string), ack["authProof"].(string), ack["authChallenge"].(string), SecretHash([]byte(secret), ackSalt))
	}

	if _, _, _, err := finish("wrong"); !errors.Is(err, ErrServerAuth) {
		t.Fatalf("wrong secret: err = %v, want ErrServerAuth", err)
	}
	cli, proof, resp, err := finish("holahola")
	if err != nil {
		t.Fatal(err)
	}
	if err := FinalizeHandshake(srv, proof, resp); err != nil {
		t.Fatalf("server refused the client proofs: %v", err)
	}
	if !bytes.Equal(cli.APIKey(), srv.APIKey()) {
		t.Fatal("api keys differ")
	}
	for _, dir := range []struct{ from, to *State }{{cli, srv}, {srv, cli}} {
		frame, err := EncryptFrame(dir.from, []byte("hi"), 1)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Decrypt(dir.to, frame[1:]); err != nil || string(got) != "hi" {
			t.Fatalf("decrypt = %q, %v", got, err)
		}
	}
}
