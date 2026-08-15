// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package fsutil holds small filesystem helpers. It is a leaf package (no
// internal imports) so every package can share them without import cycles.
package fsutil

import "os"

// AtomicWrite writes data to path via a temp file + rename, so readers never
// observe a partially written file. The temp file is removed if the rename
// fails.
func AtomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
