// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate

import "crypto/x509"

// SetPairing points pairing at a stub socket.cat, treats hosts under domain
// as relay names and verifies their certificates against pool; the restore also forgets every pending pairing, so
// a later test on a reused port starts clean.
func SetPairing(base, domain string, pool *x509.CertPool) func() {
	oldBase, oldDomain, oldRoots := pairBase, pairDomain, roots
	pairBase, pairDomain, roots = base, domain, pool
	return func() {
		pairBase, pairDomain, roots = oldBase, oldDomain, oldRoots
		pairing.Lock()
		clear(pairing.m)
		pairing.Unlock()
	}
}

// SidBytes is sidBytes: a session id's 16 bytes, nil when it is not one.
var SidBytes = sidBytes

// Printable is printable: error text with its control characters dropped.
var Printable = printable

// PoolBacklog is how many frames wait unread in id's pooled client, -1
// without one.
func PoolBacklog(id string) int {
	pool.Lock()
	defer pool.Unlock()
	if p := pool.m[id]; p != nil {
		return len(p.c.in)
	}
	return -1
}

// PoolDropSocket closes the socket of id's pooled client, as a remote that
// went away would.
func PoolDropSocket(id string) {
	pool.Lock()
	p := pool.m[id]
	pool.Unlock()
	if p != nil {
		p.c.ws.Close(1000, "")
	}
}
