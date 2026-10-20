// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate

import (
	"encoding/hex"
	"errors"
	"strings"

	"shells/internal/crypto"
)

// errSocketCat: the socket.cat route needs the relay's GUC session first.
// Device pairing (guc G1–G3) goes where it is returned: show a code + QR,
// poll until the owner approves it in the dashboard, keep the relay session
// id in remote.GUC.
var errSocketCat = errors.New("socket.cat names need device pairing, not built yet: use the blind union.cat name")

func checkURL(rawURL string) (string, error) {
	origin, host, _, err := NormalizeURL(rawURL)
	if err == nil && (host == "socket.cat" || strings.HasSuffix(host, ".socket.cat")) {
		err = errSocketCat
	}
	return origin, err
}

// Probe checks that url answers as a shells remote (TLS, then a crypto-ack),
// as ssh.Probe checks reachability before the picker asks for a password.
func Probe(rawURL string) error {
	origin, err := checkURL(rawURL)
	if err != nil {
		return err
	}
	var pin string
	c, _, err := dial(&remote{URL: origin}, &pin)
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
	origin, err := checkURL(rawURL)
	if err != nil {
		return err
	}
	if _, err := credPath(keysDir, id); err != nil {
		return err
	}
	r := &remote{URL: origin}
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
	return save(keysDir, id, r)
}
