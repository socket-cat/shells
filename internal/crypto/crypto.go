// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>
//
// Package crypto implements the shells v3 end-to-end crypto wire protocol
// using only the Go standard library.
//
//	Key agreement : ECDH on P-256 (crypto/ecdh) — raw SEC1 point, base64
//	Key derivation: HKDF-SHA256 (crypto/hmac + crypto/sha256)
//	Secret hash   : PBKDF2-SHA256, 600000 iterations (RFC 8018)
//	Auth proofs   : HMAC-SHA256 keyed by the secret hash
//	Stream AEAD   : AES-256-GCM (crypto/aes + crypto/cipher)
//	                frame body = nonce(12) || ciphertext || tag(16)
//
// It is byte-for-byte compatible with public/js/crypto.js (native WebCrypto).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"shells/internal/fsutil"
)

const (
	pbkdf2Iterations = 600000
	keyLen           = 32 // all derived keys are 256-bit
	nonceLen         = 12 // AES-GCM standard nonce
	tagLen           = 16 // AES-GCM tag
)

// labels for HKDF info binding
var (
	labelC2S = []byte("shells-v3-c2s") // client -> server
	labelS2C = []byte("shells-v3-s2c") // server -> client
	labelAPI = []byte("shells-v3-api")
)

// ---- package-level identity / secret ----

var (
	secretHash    []byte // PBKDF2(secret, salt)
	serverPriv    *ecdh.PrivateKey
	serverPubSEC1 []byte // 65-byte uncompressed point
	fingerprint   string
)

// Init resolves the server identity: derives the secret hash and loads or
// generates the persistent P-256 key pair.
func Init(secret, salt []byte, keyFile string) error {
	SetSalt(salt)
	h := pbkdf2SHA256(secret, salt, pbkdf2Iterations, keyLen)
	secretHash = h

	if err := loadOrCreateIdentity(keyFile); err != nil {
		return fmt.Errorf("crypto identity: %w", err)
	}
	return nil
}

// Shutdown zeros package-level secrets and releases the server identity.
// Called during graceful shutdown to reduce the window for memory dumps.
func Shutdown() {
	for i := range secretHash {
		secretHash[i] = 0
	}
	secretHash = nil
	for i := range saltBytes {
		saltBytes[i] = 0
	}
	saltBytes = nil
	// serverPriv.Bytes() returns a copy of the scalar, so we cannot
	// zero it through the public API — the best we can do is nil the
	// pointer.  cipher.AEAD objects inside per-connection State
	// also retain key material (Go stdlib limitation).
	serverPriv = nil
	fingerprint = ""
}

// SecretHash returns the PBKDF2-derived secret hash (used by callers that
// need to HMAC-verify the app token).
func SecretHash() []byte { return secretHash }

func loadOrCreateIdentity(keyFile string) error {
	if data, err := os.ReadFile(keyFile); err == nil {
		var k struct {
			PrivateKey  string `json:"privateKey"`
			PublicKey   string `json:"publicKey"`
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.Unmarshal(data, &k); err == nil && k.PrivateKey != "" {
			privBytes, err := base64.StdEncoding.DecodeString(k.PrivateKey)
			if err == nil {
				priv, err := ecdh.P256().NewPrivateKey(privBytes)
				if err == nil {
					serverPriv = priv
					serverPubSEC1 = priv.PublicKey().Bytes()
					fingerprint = k.Fingerprint
					return nil
				}
			}
		}
	}

	// generate fresh
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serverPriv = priv
	serverPubSEC1 = priv.PublicKey().Bytes()
	fingerprint = generateFingerprint(serverPubSEC1)

	rec := struct {
		PrivateKey  string `json:"privateKey"`
		PublicKey   string `json:"publicKey"`
		Fingerprint string `json:"fingerprint"`
	}{
		PrivateKey:  base64.StdEncoding.EncodeToString(priv.Bytes()),
		PublicKey:   base64.StdEncoding.EncodeToString(serverPubSEC1),
		Fingerprint: fingerprint,
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return err
	}
	out, _ := json.Marshal(rec)
	return fsutil.AtomicWrite(keyFile, out)
}

// generateFingerprint mirrors the JS format: SHA-256(pubkey) hex upper,
// grouped as 2-byte (4 hex char) groups separated by ':'.
func generateFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	var groups []string
	for i := 0; i < len(sum); i += 2 {
		groups = append(groups, fmt.Sprintf("%02X%02X", sum[i], sum[i+1]))
	}
	out := ""
	for i, g := range groups {
		if i > 0 {
			out += ":"
		}
		out += g
	}
	return out
}

// ---- HMAC proofs ----

func hmacSHA256(msg []byte) []byte {
	mac := hmac.New(sha256.New, secretHash)
	mac.Write(msg)
	return mac.Sum(nil)
}

// GenerateHMACProof returns base64 HMAC-SHA256(msg) keyed by the secret hash.
func GenerateHMACProof(msg []byte) string {
	return base64.StdEncoding.EncodeToString(hmacSHA256(msg))
}

// VerifyHMACProof validates a base64 proof in constant time.
func VerifyHMACProof(msg []byte, proofB64 string) bool {
	want := hmacSHA256(msg)
	got, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---- per-connection crypto state ----

// State holds the per-WebSocket crypto context.
type State struct {
	sendAEAD     cipher.AEAD // s2c (server encrypts)
	recvAEAD     cipher.AEAD // c2s (server decrypts)
	apiKey       []byte
	clientPub    []byte // 65-byte SEC1 point
	challenge    string // hex challenge string for proof-response
	challengeRaw []byte
	ready        bool
	serverAuth   string // precomputed authProof of server pubkey
}

// NewState creates a fresh per-connection state bound to the server identity.
func NewState() *State {
	return &State{
		serverAuth: GenerateHMACProof(serverPubSEC1),
	}
}

// ServerPublicKeyB64 is the server's ECDH public key (base64 SEC1 point).
func ServerPublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(serverPubSEC1)
}

// HandleInitCrypto processes the client's init-crypto message (base64 client
// pubkey), derives the session keys, and returns the crypto-ack fields.
func HandleInitCrypto(s *State, clientPubB64 string) (map[string]any, error) {
	clientPub, err := base64.StdEncoding.DecodeString(clientPubB64)
	if err != nil {
		return nil, errors.New("invalid client public key encoding")
	}
	if len(clientPub) != 65 || clientPub[0] != 0x04 {
		return nil, errors.New("invalid client public key")
	}
	clientECDH, err := ecdh.P256().NewPublicKey(clientPub)
	if err != nil {
		return nil, fmt.Errorf("invalid client public key: %w", err)
	}

	shared, err := serverPriv.ECDH(clientECDH)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}

	// keyContext = SHA-256(serverPub || clientPub)  [matches browser]
	h := sha256.New()
	h.Write(serverPubSEC1)
	h.Write(clientPub)
	var ctx [32]byte
	copy(ctx[:], h.Sum(nil))

	salt := secretHash
	s.sendAEAD, _ = newGCM(hkdf(shared, salt, concatInfo(labelS2C, ctx[:]), keyLen)) // server sends with s2c
	s.recvAEAD, _ = newGCM(hkdf(shared, salt, concatInfo(labelC2S, ctx[:]), keyLen)) // server receives c2s
	apiRaw := hkdf(shared, salt, concatInfo(labelAPI, ctx[:]), keyLen)
	s.apiKey = apiRaw
	s.clientPub = clientPub

	// challenge
	var ch [16]byte
	if _, err := rand.Read(ch[:]); err != nil {
		return nil, err
	}
	s.challenge = hex.EncodeToString(ch[:])
	s.challengeRaw = []byte(s.challenge)

	return map[string]any{
		"publicKey":     ServerPublicKeyB64(),
		"fingerprint":   fingerprint,
		"authProof":     s.serverAuth,
		"authChallenge": s.challenge,
		"salt":          hex.EncodeToString(getSalt()),
	}, nil
}

// FinalizeHandshake verifies the client's proofs and marks the state ready.
func FinalizeHandshake(s *State, clientAuthProof, proofResponse string) error {
	if s.clientPub == nil {
		return errors.New("client public key missing")
	}
	if !VerifyHMACProof(s.clientPub, clientAuthProof) {
		return errors.New("client authentication failed")
	}
	// proofResponse = HMAC(secretHash, challengeString)  [string bytes]
	if !VerifyHMACProof(s.challengeRaw, proofResponse) {
		return errors.New("challenge verification failed")
	}
	s.ready = true
	return nil
}

// APIKey returns the derived API key (raw bytes) for the auth token registry.
func (s *State) APIKey() []byte { return s.apiKey }

// Encrypt encrypts plaintext for the WS stream. Output: nonce || ct || tag.
func Encrypt(s *State, plaintext []byte) ([]byte, error) {
	if !s.ready {
		return nil, errors.New("crypto session not ready")
	}
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	ct := s.sendAEAD.Seal(nil, nonce[:], plaintext, nil)
	out := make([]byte, 0, nonceLen+len(ct))
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return out, nil
}

// EncryptFrame prepends a one-byte frame type then encrypts.
// Output: [type] || nonce || ct || tag.
func EncryptFrame(s *State, plaintext []byte, frameType byte) ([]byte, error) {
	body, err := Encrypt(s, plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(body))
	out[0] = frameType
	copy(out[1:], body)
	return out, nil
}

// Decrypt decrypts a WS stream frame body (nonce || ct || tag).
func Decrypt(s *State, data []byte) ([]byte, error) {
	if !s.ready {
		return nil, errors.New("crypto session not ready")
	}
	if len(data) < nonceLen+tagLen {
		return nil, errors.New("invalid encrypted payload length")
	}
	nonce := data[:nonceLen]
	ct := data[nonceLen:]
	return s.recvAEAD.Open(nil, nonce, ct, nil)
}

// EncryptApiPayload encrypts a JSON request/response body.
func EncryptApiPayload(apiKey []byte, plaintext []byte) (map[string]string, error) {
	a, err := newGCM(apiKey)
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	ct := a.Seal(nil, nonce[:], plaintext, nil)
	return map[string]string{
		"nonce":      base64.StdEncoding.EncodeToString(nonce[:]),
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// DecryptApiPayload decrypts a JSON request/response body.
func DecryptApiPayload(apiKey []byte, nonceB64, ctB64 string) ([]byte, error) {
	a, err := newGCM(apiKey)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil || len(nonce) != nonceLen {
		return nil, errors.New("invalid nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return nil, errors.New("invalid ciphertext")
	}
	return a.Open(nil, nonce, ct, nil)
}

// Destroy zeroes the derived key material.
func Destroy(s *State) {
	if s == nil {
		return
	}
	for i := range s.apiKey {
		s.apiKey[i] = 0
	}
	s.apiKey = nil
	s.ready = false
}

// ---- helpers ----

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func concatInfo(label, ctx []byte) []byte {
	info := make([]byte, 0, len(label)+len(ctx))
	info = append(info, label...)
	info = append(info, ctx...)
	return info
}

// hkdf is RFC 5869 HKDF-SHA256.
func hkdf(ikm, salt, info []byte, length int) []byte {
	prk := hkdfExtract(salt, ikm)
	return hkdfExpand(prk, info, length)
}

func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	hashLen := sha256.Size
	n := (length + hashLen - 1) / hashLen
	var t []byte
	okm := make([]byte, 0, n*hashLen)
	for i := byte(1); len(okm) < length; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(t[:0])
		okm = append(okm, t...)
	}
	return okm[:length]
}

// pbkdf2SHA256 is PBKDF2 (RFC 8018) with HMAC-SHA256.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	T := make([]byte, hashLen)
	var blockBytes [4]byte
	for block := 1; block <= numBlocks; block++ {
		blockBytes[0] = byte(block >> 24)
		blockBytes[1] = byte(block >> 16)
		blockBytes[2] = byte(block >> 8)
		blockBytes[3] = byte(block)

		prf.Reset()
		prf.Write(salt)
		prf.Write(blockBytes[:])
		T = prf.Sum(T[:0])
		copy(U, T)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(U[:0])
			for i := range T {
				T[i] ^= U[i]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}

// getSalt returns the salt bytes; salt is held by config but mirrored here via
// a setter to avoid an import cycle.
var saltBytes []byte

// SetSalt is called by config at startup.
func SetSalt(s []byte) { saltBytes = make([]byte, len(s)); copy(saltBytes, s) }

func getSalt() []byte { return saltBytes }
