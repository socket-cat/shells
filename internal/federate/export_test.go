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
