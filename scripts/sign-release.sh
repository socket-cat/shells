#!/usr/bin/env bash
# Sign a release checksums file with the offline Ed25519 key and emit the raw
# 64-byte signature to <checksums>.sig — the artifact hosted on socket.cat.
#
# Usage:
#   scripts/sign-release.sh <version> [checksums.txt] [output.sig]
#
# The key is NEVER read from the environment in CI. This runs on the signer's
# offline machine:
#   SHELLS_SIGNING_KEY=/path/to/signing-primary.key ./scripts/sign-release.sh 1.2.46
#
# Set -x to a git commit hash to make signing deterministic if desired; the
# server only verifies the signature, so a random nonce is also fine.
set -euo pipefail

VERSION="${1:?usage: sign-release.sh <version> [checksums.txt] [output.sig]}"
CHECKSUMS="${2:-checksums.txt}"
OUT="${3:-${CHECKSUMS}.sig}"
KEY="${SHELLS_SIGNING_KEY:-}"

if [ -z "$KEY" ]; then
  echo "error: SHELLS_SIGNING_KEY not set (path to the offline ed25519 private key)" >&2
  exit 1
fi
if [ ! -f "$CHECKSUMS" ]; then
  echo "error: $CHECKSUMS not found" >&2
  exit 1
fi
if [ ! -f "$KEY" ]; then
  echo "error: signing key $KEY not found" >&2
  exit 1
fi

# Require the version header (binds version into the signed bytes).
head -1 "$CHECKSUMS" | grep -q "^# shells ${VERSION}$" || {
  echo "error: first line must be '# shells ${VERSION}'" >&2
  exit 1
}

# The signature is over the exact raw bytes of checksums.txt.
# Signing is done through a tiny Go helper (pure stdlib crypto/ed25519).
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/sign.go" <<'GOEOF'
package main

import (
	"crypto/ed25519"
	"os"
)

func main() {
	keyRaw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var key ed25519.PrivateKey
	switch len(keyRaw) {
	case ed25519.PrivateKeySize:
		key = ed25519.PrivateKey(keyRaw)
	case ed25519.SeedSize:
		key = ed25519.NewKeyFromSeed(keyRaw)
	default:
		panic("bad signing key length")
	}
	msg, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[3], ed25519.Sign(key, msg), 0o644); err != nil {
		panic(err)
	}
}
GOEOF

"${GO:-go}" run "$TMPDIR/sign.go" "$KEY" "$CHECKSUMS" "$OUT"

echo "wrote $OUT ($(wc -c < "$OUT") bytes)"
