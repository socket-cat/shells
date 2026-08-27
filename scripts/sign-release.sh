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

# Absolutize path arguments against the INVOKER's CWD before changing
# directory — relative args (devel/README.md: `checksums.txt checksums.txt.sig`,
# `SHELLS_SIGNING_KEY=devel/keys/...`) resolve where the caller meant them,
# from any CWD, and every later read/validate/mutate sees one absolute path
# (no split-brain between the pre-cd and post-cd views).
abspath() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *)  printf '%s\n' "$PWD/$1" ;;
  esac
}
if [ -z "$KEY" ]; then
  echo "error: SHELLS_SIGNING_KEY not set (path to the offline ed25519 private key)" >&2
  exit 1
fi
CHECKSUMS=$(abspath "$CHECKSUMS")
OUT=$(abspath "$OUT")
KEY=$(abspath "$KEY")

# All paths below (dist/, checksums.txt) are repo-root anchored; the caller's
# arguments were absolutized above.
cd "$(dirname "$0")/.." || exit 1

if [ ! -f "$CHECKSUMS" ]; then
  echo "error: $CHECKSUMS not found" >&2
  exit 1
fi
if [ ! -f "$KEY" ]; then
  echo "error: signing key $KEY not found" >&2
  exit 1
fi

# Require the version header (binds version into the signed bytes). Single
# check, on the resolved absolute path, after cd.
head -1 "$CHECKSUMS" | grep -q "^# shells ${VERSION}$" || {
  echo "error: first line must be '# shells ${VERSION}'" >&2
  exit 1
}

# --- SBOM coverage (CRA readiness, devel/qa/08) --------------------------
# The Ed25519 signature must cover the release SBOMs too. Content-keyed
# merge: every dist/*.spdx.json gets exactly one "<sha256>  <name>" line
# (bare name, same format sha256sum writes for the binaries). Stale hashes
# are replaced in place, absent ones appended, same-name duplicates dropped
# — idempotent and stale-hash-safe across re-signs. Signing with no dist
# SBOMs at all is a hard fail; legacy/no-SBOM flows opt out explicitly.
# sha256 in sha256sum's output format ("hash  name"); shasum -a 256 emits the
# identical two-space format where sha256sum is absent (mirrors gen-sbom.sh).
digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

if [ "${SHELLS_SIGN_NO_SBOM:-0}" = "1" ]; then
  echo "note: SHELLS_SIGN_NO_SBOM=1 — signing WITHOUT SBOM coverage" >&2
else
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "error: need sha256sum or shasum on PATH for SBOM digests" >&2
    exit 1
  fi
  sbom_found=0
  for sbom in dist/*.spdx.json; do
    [ -f "$sbom" ] || continue
    sbom_found=1
    base=$(basename "$sbom")
    expected=$( (cd dist && digest "$base") )
    tmp=$(mktemp "$CHECKSUMS.tmp.XXXXXX")
    # Match on the exact basename as the line's LAST whitespace field —
    # anchored by construction, no substring false positives (a.b.spdx.json
    # vs b.spdx.json stay distinct).
    awk -v name="$base" -v newline="$expected" '
      BEGIN { replaced = 0 }
      $NF == name { if (!replaced) { print newline; replaced = 1 } next }
      { print }
      END { if (!replaced) print newline }
    ' "$CHECKSUMS" > "$tmp" || { rm -f "$tmp"; exit 1; }
    mv "$tmp" "$CHECKSUMS" || exit 1
    chmod 644 "$CHECKSUMS"
  done
  [ "$sbom_found" -eq 1 ] || {
    echo "error: no dist/*.spdx.json — run scripts/gen-sbom.sh first, or set SHELLS_SIGN_NO_SBOM=1 to skip" >&2
    exit 1
  }
fi

# Manual post-signing steps (not CI-automated yet — devel/qa/08 G-1/G-5):
# re-upload the SIGNED checksums.txt to the GitHub release (re-sign without
# re-upload ⇒ socket.cat sig diverges from GitHub's bytes) and attach
# dist/*.spdx.json to the release, or the signature covers nothing shipped.

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
