// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"shells/internal/crypto"
	"shells/internal/websocket"
)

// Frame types of the shells stream (wshandler msgTypeData/msgTypeControl).
const (
	frameData    byte = 0
	frameControl byte = 1
)

// replyTimeout bounds each handshake reply and API call.
const replyTimeout = 30 * time.Second

// client is one connection to a remote: the WebSocket carries the terminal
// stream and keeps the session token alive (the remote revokes it when the
// socket closes); /api calls go over HTTP. Both pass the same TLS check.
type client struct {
	r      *remote
	tls    *tls.Config
	header http.Header // the GUC cookie when r has one; no Origin (see dial)
	ws     *websocket.Conn
	in     chan []byte // frames from the remote, in order; closed with the socket
	reason string      // close reason, readable once in is closed

	hs    *crypto.ClientHandshake
	state *crypto.State
	token string
	http  *http.Client
}

// ack is the remote's crypto-ack.
type ack struct {
	Type, PublicKey, Fingerprint, AuthProof, AuthChallenge, Salt string
}

// dial opens the socket and sends init-crypto; the caller checks the ack's
// identity before finish. learn is tlsConfig's (setup only).
func dial(r *remote, learn *string) (*client, *ack, error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil, nil, err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	// No Origin header: the remote allows an absent one (non-browser
	// client), while its check of a present one reads the Host header that
	// Go's server strips, so with SHELLS_CHECK_ORIGIN=true and no proxy any
	// Origin is refused.
	pin := r.TLSPin
	if r.GUC != "" {
		// The GUC is a bearer credential for the whole relay route: it goes
		// only to a certificate the roots vouch for, never on first use.
		pin, learn = "", nil
	}
	c := &client{r: r, tls: tlsConfig(u.Hostname(), pin, learn), header: http.Header{}, in: make(chan []byte, 64)}
	if r.GUC != "" {
		c.header.Set("Cookie", "GUC="+r.GUC)
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: replyTimeout}, "tcp", net.JoinHostPort(u.Hostname(), port), c.tls)
	if err != nil {
		return nil, nil, err
	}
	c.ws, err = websocket.Client(conn, &url.URL{Scheme: "wss", Host: u.Host, Path: "/ws"}, c.header)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	c.ws.OnMessage = func(p []byte, _ bool) { c.in <- p }
	c.ws.OnClose = func(_ int, reason string) { c.reason = reason; close(c.in) }
	go c.ws.Start()

	if c.hs, err = crypto.NewClientHandshake(); err != nil {
		c.close()
		return nil, nil, err
	}
	hello, _ := json.Marshal(map[string]string{"type": "init-crypto", "publicKey": c.hs.PublicKeyB64()})
	c.ws.SendText(hello)
	p, err := c.recv(replyTimeout)
	if err != nil {
		c.close()
		return nil, nil, err
	}
	var a ack
	if json.Unmarshal(p, &a) != nil || a.Type != "crypto-ack" || a.Salt == "" {
		c.close()
		return nil, nil, errors.New("not a shells remote (no crypto-ack)")
	}
	return c, &a, nil
}

// connect dials a remote added before: identity and salt must match the pins
// in r, then the stored hash finishes the handshake.
func connect(r *remote) (*client, error) {
	c, a, err := dial(r, nil)
	if relayRefused(err) && r.GUC != "" {
		return nil, errors.New("socket.cat refused this server's pairing (unused for 7 days, or revoked): add the connection again in the picker")
	}
	if err != nil {
		return nil, err
	}
	fp, err := crypto.Fingerprint(a.PublicKey)
	switch {
	case err != nil:
	case fp != r.Fingerprint:
		err = fmt.Errorf("remote identity changed (fingerprint %s, pinned %s): refusing; if expected, remove the connection and add it again", fp, r.Fingerprint)
	case a.Salt != r.Salt:
		err = errors.New("the remote's secret changed (new salt): remove the connection and add it again")
	default:
		hash, _ := hex.DecodeString(r.SecretHash)
		err = c.finish(a, hash)
	}
	if err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

// finish proves the secret (crypto-ready) and takes the session token from
// the encrypted auth-success.
func (c *client) finish(a *ack, secretHash []byte) error {
	st, proof, resp, err := c.hs.Finish(a.PublicKey, a.AuthProof, a.AuthChallenge, secretHash)
	if errors.Is(err, crypto.ErrServerAuth) {
		return ErrWrongSecret
	}
	if err != nil {
		return err
	}
	c.state = st
	ready, _ := json.Marshal(map[string]string{"type": "crypto-ready", "authProof": proof, "proofResponse": resp})
	c.ws.SendText(ready)
	p, err := c.recv(replyTimeout)
	if err != nil {
		return err
	}
	typ, plain, err := c.decrypt(p)
	var m struct{ Type, SessionToken string }
	if err != nil || typ != frameControl || json.Unmarshal(plain, &m) != nil || m.Type != "auth-success" || m.SessionToken == "" {
		return errors.New("handshake: no auth-success")
	}
	c.token = m.SessionToken
	c.http = &http.Client{
		Timeout:       replyTimeout,
		Transport:     &http.Transport{TLSClientConfig: c.tls},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}

func (c *client) recv(timeout time.Duration) ([]byte, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case p, ok := <-c.in:
		if !ok {
			return nil, c.closedErr()
		}
		return p, nil
	case <-t.C:
		return nil, errors.New("the remote did not answer")
	}
}

func (c *client) closedErr() error {
	if c.reason != "" {
		return fmt.Errorf("the remote closed the connection: %s", c.reason)
	}
	return errors.New("the remote closed the connection")
}

// decrypt opens a stream frame: [type] || nonce || ct || tag.
func (c *client) decrypt(p []byte) (byte, []byte, error) {
	if len(p) < 1 {
		return 0, nil, errors.New("empty frame")
	}
	plain, err := crypto.Decrypt(c.state, p[1:])
	return p[0], plain, err
}

func (c *client) send(typ byte, plain []byte) error {
	frame, err := crypto.EncryptFrame(c.state, plain, typ)
	if err != nil {
		return err
	}
	if !c.ws.SendBinary(frame) {
		return errors.New("connection closed")
	}
	return nil
}

func (c *client) control(msg map[string]any) error {
	b, _ := json.Marshal(msg)
	return c.send(frameControl, b)
}

// data sends terminal input for the session whose 16-byte id is sid.
func (c *client) data(sid, input []byte) error {
	return c.send(frameData, append(append(make([]byte, 0, 16+len(input)), sid...), input...))
}

// ErrWrongSecret: the remote's proof does not match the secret (hash).
var ErrWrongSecret = errors.New("wrong secret: the remote's proof does not match")

// APIError is an error reply of the remote's /api, with its machine code
// (e.g. cwd_unusable, command_not_found) when it sent one.
type APIError struct{ Path, Msg, Code string }

func (e *APIError) Error() string { return e.Path + ": " + e.Msg }

// Call is one encrypted /api request to the remote id over a connection of
// its own, for the ls / which / paste forwards.
func Call(keysDir, id, path string, body map[string]any) (map[string]any, error) {
	r, err := load(keysDir, id)
	if err != nil {
		return nil, err
	}
	c, err := connect(r)
	if err != nil {
		return nil, err
	}
	defer c.close()
	return c.call(path, body)
}

// call is one encrypted /api request (always POST, the verb in _method, like
// the browser). A reply the remote did not encrypt is an error from before
// decryption (401, 400), never data.
func (c *client) call(path string, body map[string]any) (map[string]any, error) {
	plain, _ := json.Marshal(body)
	enc, err := crypto.EncryptApiPayload(c.state.APIKey(), plain)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(enc)
	req, err := http.NewRequest(http.MethodPost, c.r.URL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header = c.header.Clone()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shells-Encrypted", "1")
	req.Header.Set("X-Shells-Token", c.token)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	encrypted := res.Header.Get("X-Shells-Encrypted") == "1"
	if encrypted {
		var e struct{ Nonce, Ciphertext string }
		if err := json.Unmarshal(data, &e); err != nil {
			return nil, err
		}
		if data, err = crypto.DecryptApiPayload(c.state.APIKey(), e.Nonce, e.Ciphertext); err != nil {
			return nil, fmt.Errorf("%s: undecryptable reply", path)
		}
	}
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if msg, _ := out["error"].(string); msg != "" {
		code, _ := out["code"].(string)
		return nil, &APIError{path, msg, code}
	}
	if !encrypted || res.StatusCode >= 300 || out == nil {
		return nil, &APIError{Path: path, Msg: res.Status}
	}
	return out, nil
}

// close ends the socket (the remote revokes the token with it) and waits,
// bounded, for the close frame to go out.
func (c *client) close() {
	c.ws.Close(1000, "")
	select {
	case <-c.ws.Done():
	case <-time.After(2 * time.Second):
	}
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
}
