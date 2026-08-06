// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package release implements cryptographic verification of published Shells
// releases. The trust model is cross-channel: release content comes from
// GitHub, the Ed25519 signature comes from socket.cat, and the verifying
// public keys are pinned in the binary. No single channel compromise yields a
// forged verified release.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

type pinnedKey struct {
	fingerprint string
	pub         ed25519.PublicKey
}

// pinnedKeys are the offline-held signing keys (primary + backup). Private
// keys never live in CI; rotation is a documented manual procedure.
var pinnedKeys = []pinnedKey{
	{
		fingerprint: "d6615b9e858ed590",
		pub:         mustDecodePub("d5f143c752145016927cc3d82c4f4db3e6fc859747964f3c277259994686a094"),
	},
	{
		fingerprint: "f4b8c3d92b880b6a",
		pub:         mustDecodePub("02737c868e5d5024b87a15a14ca6b93e4a5e44e4af3157d2cfba685c751e7afb"),
	},
}

func mustDecodePub(s string) ed25519.PublicKey {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("release: bad pinned key hex: " + err.Error())
	}
	return ed25519.PublicKey(b)
}

// Init validates the pinned keys' lengths. ed25519.Verify panics on a
// wrong-length public key, so this must run once at startup.
func Init() error {
	for _, k := range pinnedKeys {
		if len(k.pub) != ed25519.PublicKeySize {
			return fmt.Errorf("release: pinned key %s has bad length %d", k.fingerprint, len(k.pub))
		}
	}
	return nil
}

// Fingerprints returns the pinned key fingerprints (primary first).
func Fingerprints() []string {
	out := make([]string, 0, len(pinnedKeys))
	for _, k := range pinnedKeys {
		out = append(out, k.fingerprint)
	}
	return out
}

// FingerprintOf derives the display fingerprint for a public key (first 8
// bytes of its SHA-256, hex).
func FingerprintOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// verify checks sig over msg against every pinned key and returns the
// fingerprint of the matching key. It requires a full-size signature.
func verify(msg, sig []byte) (string, error) {
	if len(sig) != ed25519.SignatureSize {
		return "", errors.New("release: bad signature length")
	}
	for _, k := range pinnedKeys {
		if ed25519.Verify(k.pub, msg, sig) {
			return k.fingerprint, nil
		}
	}
	return "", errors.New("release: signature verification failed")
}
