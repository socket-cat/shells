// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package crypto

// Client half of the handshake, for a shells that connects to another one
// (internal/federate). It mirrors HandleInitCrypto / FinalizeHandshake but
// touches no package state: the secret hash comes in as an argument, so one
// process can hold several remotes.

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// ErrServerAuth means the remote's authProof does not match the secret hash:
// a wrong secret, or not the remote it claims to be.
var ErrServerAuth = errors.New("server authentication failed")

// ClientHandshake is one handshake in flight: the ephemeral P-256 key that
// init-crypto sends.
type ClientHandshake struct{ priv *ecdh.PrivateKey }

// NewClientHandshake generates the ephemeral key.
func NewClientHandshake() (*ClientHandshake, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ClientHandshake{priv: priv}, nil
}

// PublicKeyB64 is the init-crypto publicKey field.
func (h *ClientHandshake) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(h.priv.PublicKey().Bytes())
}

// Fingerprint is the identity fingerprint of a server public key (the
// crypto-ack publicKey), computed from the key itself rather than taken from
// the ack's own fingerprint field.
func Fingerprint(serverPubB64 string) (string, error) {
	pub, err := parseServerPub(serverPubB64)
	if err != nil {
		return "", err
	}
	return generateFingerprint(pub.Bytes()), nil
}

// SecretHash derives the handshake key from the secret and the remote's salt
// (the crypto-ack salt), as Init does on the server.
func SecretHash(secret, salt []byte) []byte {
	return pbkdf2SHA256(secret, salt, pbkdf2Iterations, keyLen)
}

// Finish verifies the server's authProof = HMAC(secretHash, serverPub) before
// anything else, derives the session keys and returns a ready State plus the
// crypto-ready proofs: HMAC(clientPub) and HMAC(challenge).
func (h *ClientHandshake) Finish(serverPubB64, authProof, challenge string, secretHash []byte) (s *State, clientProof, proofResponse string, err error) {
	// The answer is HMAC(secretHash, challenge), and secretHash is also the
	// HKDF salt: the session PRK is HMAC(secretHash, ECDH secret). So only
	// the shape every server sends (v1.2.0 on: 16 random bytes, lowercase
	// hex) is answered, never a chosen value such as an ECDH secret.
	if len(challenge) != 32 || strings.Trim(challenge, "0123456789abcdef") != "" {
		return nil, "", "", errors.New("invalid server challenge")
	}
	serverPub, err := parseServerPub(serverPubB64)
	if err != nil {
		return nil, "", "", err
	}
	proof, err := base64.StdEncoding.DecodeString(authProof)
	if err != nil || !hmac.Equal(proof, macWith(secretHash, serverPub.Bytes())) {
		return nil, "", "", ErrServerAuth
	}
	shared, err := h.priv.ECDH(serverPub)
	if err != nil {
		return nil, "", "", err
	}
	clientPub := h.priv.PublicKey().Bytes()
	c2s, s2c, api := sessionKeys(shared, secretHash, serverPub.Bytes(), clientPub)
	s = &State{apiKey: api, clientPub: clientPub, ready: true}
	if s.sendAEAD, err = newGCM(c2s); err != nil {
		return nil, "", "", err
	}
	if s.recvAEAD, err = newGCM(s2c); err != nil {
		return nil, "", "", err
	}
	b64 := base64.StdEncoding.EncodeToString
	return s, b64(macWith(secretHash, clientPub)), b64(macWith(secretHash, []byte(challenge))), nil
}

// parseServerPub decodes a base64 uncompressed P-256 point; NewPublicKey
// rejects any other encoding and points off the curve.
func parseServerPub(b64 string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("invalid server public key")
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, errors.New("invalid server public key")
	}
	return pub, nil
}
