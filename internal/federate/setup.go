// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate

import (
	"encoding/hex"
	"errors"

	"shells/internal/crypto"
)

// remoteFor is the remote to dial for url. A socket.cat name sits behind the
// relay's GUC gate: it carries the session the owner approved, or the error
// is a PairError with the code to approve.
func remoteFor(rawURL string) (*remote, error) {
	origin, host, _, err := NormalizeURL(rawURL)
	if err != nil {
		return nil, err
	}
	r := &remote{URL: origin}
	if isSocketCat(host) {
		r.GUC, err = relaySession(origin)
	}
	return r, err
}

// Probe checks that url answers as a shells remote (TLS, then a crypto-ack),
// as ssh.Probe checks reachability before the picker asks for a password.
func Probe(rawURL string) error {
	r, err := remoteFor(rawURL)
	if err != nil {
		return err
	}
	var pin string
	c, _, err := dial(r, &pin)
	if relayRefused(err) && r.GUC != "" {
		forgetPairing(r.URL)
		_, err = relaySession(r.URL)
	}
	if err != nil {
		return err
	}
	c.close()
	return nil
}

// Setup proves the secret against url and stores the credential as
// keysDir/<id>.shells, as ssh.SetupKey installs a key with the password: the
// secret is used once and dropped. The identity and the TLS leaf are pinned
// on this first use (accept-new); a wrong secret writes nothing.
func Setup(keysDir, id, rawURL string, secret []byte) error {
	if _, err := credPath(keysDir, id); err != nil {
		return err
	}
	r, err := remoteFor(rawURL)
	if err != nil {
		return err
	}
	var pin string
	c, a, err := dial(r, &pin)
	if err != nil {
		return err
	}
	defer c.close()
	fp, err := crypto.Fingerprint(a.PublicKey)
	if err != nil {
		return err
	}
	salt, err := hex.DecodeString(a.Salt)
	if err != nil || len(salt) == 0 {
		return errors.New("the remote sent a bad salt")
	}
	hash := crypto.SecretHash(secret, salt)
	if err := c.finish(a, hash); err != nil {
		return err
	}
	r.Salt, r.SecretHash, r.Fingerprint, r.TLSPin = a.Salt, hex.EncodeToString(hash), fp, pin
	if old, _ := load(keysDir, id); old != nil && old.GUC != r.GUC {
		Unpair(keysDir, id)
	}
	if err := save(keysDir, id, r); err != nil {
		return err
	}
	forgetPairing(r.URL)
	return nil
}
