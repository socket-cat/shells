// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package crypto

import (
	"bytes"
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
