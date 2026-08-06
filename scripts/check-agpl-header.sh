#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>
#
# Pre-commit guard: ensures every staged source file we author carries an
# AGPL-3.0 header. Vendor code (xterm, web fonts, build output) is excluded.
set -euo pipefail

# Third-party / generated paths — never checked for a header.
EXCLUDED=(
  "public/js/xterm.js"
  "public/js/xterm-addon-fit.js"
  "public/js/xterm-addon-webgl.js"
  "public/js/xterm-addon-unicode11.js"
  "public/js/xterm-addon-clipboard.js"
  "public/js/xterm-addon-web-links.js"
  "public/js/xterm-addon-search.js"
  "public/css/xterm.css"
  "public/fonts/"
  "dist/"
)

is_excluded() {
  local f="$1"
  for ex in "${EXCLUDED[@]}"; do
    [[ "$f" == *"$ex"* ]] && return 0
  done
  return 1
}

# Collect staged added/copied/modified files, dropping excluded ones.
staged=()
while IFS= read -r f; do
  if [ -f "$f" ] && ! is_excluded "$f"; then
    staged+=("$f")
  fi
done < <(git diff --cached --name-only --diff-filter=ACM)

[ ${#staged[@]} -eq 0 ] && exit 0

missing=()
for f in "${staged[@]}"; do
  case "$f" in
    *.go)
      head -5 "$f" | grep -qi 'SPDX-License-Identifier:.*AGPL' || missing+=("$f")
      ;;
    *.js|*.css)
      head -20 "$f" | grep -qi 'GNU Affero General Public License' || missing+=("$f")
      ;;
    *.html)
      head -10 "$f" | grep -qiE 'GNU Affero General Public License|AGPL-3\.0' || missing+=("$f")
      ;;
  esac
done

if [ ${#missing[@]} -gt 0 ]; then
  echo "ERROR: the following staged files are missing an AGPL-3.0 header:" >&2
  for f in "${missing[@]}"; do
    echo "  - $f" >&2
  done
  cat >&2 <<'EOF'

Go files need (first lines):
  // SPDX-License-Identifier: AGPL-3.0-or-later
  // Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

JS/CSS/HTML files need the full "GNU Affero General Public License" block.
EOF
  exit 1
fi
