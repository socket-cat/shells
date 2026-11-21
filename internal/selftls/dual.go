// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package selftls

import (
	"crypto/tls"
	"io"
	"net"
	"time"
)

// Dual wraps a listener so one port speaks both TLS and plain http: a
// connection whose first byte is a TLS handshake record (0x16) is returned as
// a *tls.Conn (net/http then handshakes it and sets Request.TLS), anything
// else as-is. A plain-http reverse proxy keeps working unchanged, and a
// browser that typed http://host:port gets the page, which moves itself to
// https when it has no secure context (shell-sessions.js getWs).
func Dual(ln net.Listener, cfg *tls.Config) net.Listener {
	l := &dualListener{Listener: ln, cfg: cfg, out: make(chan accepted), done: make(chan struct{})}
	go l.loop()
	return l
}

type accepted struct {
	c   net.Conn
	err error
}

type dualListener struct {
	net.Listener
	cfg  *tls.Config
	out  chan accepted
	done chan struct{}
}

func (l *dualListener) loop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			select {
			case l.out <- accepted{err: err}:
				continue // net/http backs off on temporary errors, stops on the rest
			case <-l.done:
				return
			}
		}
		// Peek off the accept loop, so a silent client stalls only itself.
		go func() {
			first := make([]byte, 1)
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(c, first); err != nil {
				c.Close()
				return
			}
			c.SetReadDeadline(time.Time{})
			var conn net.Conn = &prefixConn{Conn: c, first: first}
			if first[0] == 0x16 {
				conn = tls.Server(conn, l.cfg)
			}
			select {
			case l.out <- accepted{c: conn}:
			case <-l.done:
				c.Close()
			}
		}()
	}
}

func (l *dualListener) Accept() (net.Conn, error) {
	select {
	case a := <-l.out:
		return a.c, a.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *dualListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return l.Listener.Close()
}

// prefixConn replays the peeked byte ahead of the connection. It forwards the
// TCP methods the websocket layer looks up by interface: without CloseWrite
// a pipe exec's close would reset the socket and drop its last output.
type prefixConn struct {
	net.Conn
	first []byte
}

func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *prefixConn) SetNoDelay(on bool) error {
	if nd, ok := c.Conn.(interface{ SetNoDelay(bool) error }); ok {
		return nd.SetNoDelay(on)
	}
	return nil
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.first) > 0 && len(p) > 0 {
		p[0] = c.first[0]
		c.first = nil
		return 1, nil
	}
	return c.Conn.Read(p)
}
