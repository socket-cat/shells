#!/bin/sh
# gen-sbom.sh — generate a SPDX 2.3 JSON SBOM per Shells build target.
#
# Usage:
#   scripts/gen-sbom.sh [os/arch ...]      default: all 6 release targets
#   scripts/gen-sbom.sh linux/amd64
#
# Requires the matching dist/shells-<os>-<arch> binaries (AGENTS.md
# §Cross-Compile). Output: dist/shells-<os>-<arch>.spdx.json.
#
# Release wiring: attach the SBOMs to the GitHub release and fold them into
# checksums.txt — scripts/sign-release.sh picks up dist/*.spdx.json before
# signing, so the Ed25519 signature covers the SBOMs too.
#
# Offline and deterministic: reads only VERSION, go.mod, `go version` and the
# local binaries; byte-identical output for a given UTC date. No network.
set -u

cd "$(dirname "$0")/.." || exit 1

[ -f VERSION ] || { echo "error: VERSION not found (run at repo root)" >&2; exit 1; }
VERSION=$(tr -d ' \t\r\n' < VERSION)
VERSION=${VERSION#v}
[ -n "$VERSION" ] || { echo "error: VERSION file is empty" >&2; exit 1; }

# Hardening: VERSION and target names land in JSON strings and output
# filenames — allow only [A-Za-z0-9._+~-]+ so nothing can inject into either.
case $VERSION in
  *[!A-Za-z0-9._+~-]*)
    echo "error: bad VERSION '$VERSION' (allowed: [A-Za-z0-9._+~-])" >&2
    exit 1
    ;;
esac

MODULE=$(sed -n 's/^module[[:space:]][[:space:]]*\([^[:space:]]*\).*/\1/p' go.mod)
[ -n "$MODULE" ] || { echo "error: module name not found in go.mod" >&2; exit 1; }

GO=${GO:-go}
command -v "$GO" >/dev/null 2>&1 || { echo "error: $GO not found (set GO or PATH)" >&2; exit 1; }
TOOLCHAIN=$("$GO" version | sed 's/^go version go//; s/[[:space:]].*//')
[ -n "$TOOLCHAIN" ] || { echo "error: cannot determine Go toolchain version" >&2; exit 1; }

NOW=$(date -u +%Y-%m-%dT00:00:00Z) # date-granular: byte-identical output per UTC day
SUPPLIER="Shells project"
LICENSE="AGPL-3.0-or-later"
COPYRIGHT="Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>"
REPO="socket-cat/shells"

# sha256 of $1 as bare hex; empty if no tool exists.
digest() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# JSON validity check: python3 when present, otherwise a stdlib-only Go
# one-liner (this project always has a Go toolchain). Also asserts the key
# SPDX fields exist.
VALGO=$(mktemp "${TMPDIR:-/tmp}/sbom-val.XXXXXX.go")
trap 'rm -f "$VALGO"' EXIT
cat > "$VALGO" <<'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		fmt.Fprintln(os.Stderr, "invalid JSON: ", err)
		os.Exit(1)
	}
	for _, k := range []string{"spdxVersion", "dataLicense", "SPDXID",
		"documentNamespace", "creationInfo", "packages", "relationships"} {
		if _, ok := v[k]; !ok {
			fmt.Fprintln(os.Stderr, "missing SPDX field: ", k)
			os.Exit(1)
		}
	}
}
EOF

validate() {
	if command -v python3 >/dev/null 2>&1; then
		python3 -m json.tool "$1" >/dev/null
	else
		"$GO" run "$VALGO" "$1"
	fi
}

TARGETS="${*:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 freebsd/amd64 freebsd/arm64}"

for target in $TARGETS; do
	case $target in
	*/*) ;;
	*)
		echo "error: bad target '$target' (want os/arch)" >&2
		exit 1
		;;
	esac
	os=${target%/*}
	arch=${target#*/}

	case $os$arch in
	*[!A-Za-z0-9._+~-]*)
		echo "error: bad target '$target' (allowed: [A-Za-z0-9._+~-])" >&2
		exit 1
		;;
	esac

	bin="dist/shells-$os-$arch"
	if [ ! -f "$bin" ]; then
		echo "error: $bin missing — run the cross-compile block first (AGENTS.md)" >&2
		exit 1
	fi
	SHA=$(digest "$bin")
	if [ -z "$SHA" ]; then
		echo "error: no sha256 tool (sha256sum/shasum) available" >&2
		exit 1
	fi

	out="dist/shells-$os-$arch.spdx.json"
	cat > "$out" <<EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "shells-$os-$arch-$VERSION",
  "documentNamespace": "https://socket.cat/spdx/shells/$VERSION/$os-$arch/$NOW",
  "creationInfo": {
    "created": "$NOW",
    "creators": [
      "Organization: $SUPPLIER",
      "Tool: gen-sbom.sh"
    ]
  },
  "packages": [
    {
      "name": "$MODULE",
      "SPDXID": "SPDXRef-Package-shells",
      "versionInfo": "$VERSION",
      "supplier": "Organization: $SUPPLIER",
      "downloadLocation": "https://github.com/$REPO/releases/tag/v$VERSION",
      "filesAnalyzed": false,
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "$SHA"
        }
      ],
      "licenseConcluded": "$LICENSE",
      "licenseDeclared": "$LICENSE",
      "copyrightText": "$COPYRIGHT",
      "primaryPackagePurpose": "APPLICATION",
      "comment": "Static Go binary for $os/$arch. $MODULE is pure Go standard library: no third-party modules (go.mod declares no requires), so the Go standard library and toolchain are the only components. They are represented by the go-toolchain package below. One SBOM per release target; this document describes that target only.",
      "externalReferences": [
        {
          "referenceCategory": "DISTRIBUTION",
          "referenceType": "distribution",
          "referenceLocator": "https://github.com/$REPO/releases"
        },
        {
          "referenceCategory": "SECURITY",
          "referenceType": "security-page",
          "referenceLocator": "https://github.com/$REPO/blob/main/SECURITY.md"
        }
      ]
    },
    {
      "name": "go-toolchain",
      "SPDXID": "SPDXRef-Package-go-toolchain",
      "versionInfo": "$TOOLCHAIN",
      "supplier": "Organization: Go project",
      "downloadLocation": "https://go.dev/dl/",
      "filesAnalyzed": false,
      "licenseConcluded": "BSD-3-Clause",
      "licenseDeclared": "BSD-3-Clause",
      "copyrightText": "NOASSERTION",
      "comment": "Go toolchain ($GO version) that produced this binary; the statically linked Go standard library ships with it. There are no other components in the product."
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-shells"
    },
    {
      "spdxElementId": "SPDXRef-Package-go-toolchain",
      "relationshipType": "BUILD_TOOL_OF",
      "relatedSpdxElement": "SPDXRef-Package-shells"
    }
  ]
}
EOF
	validate "$out" || {
		echo "error: $out failed JSON/SPDX validation" >&2
		exit 1
	}
	echo "wrote $out (shells $VERSION, toolchain $TOOLCHAIN, sha256 $SHA)"
done
