#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>
#
# Canonical build — every build path (dev, QC, release, docs) calls this so
# flags never drift. Honours GOOS/GOARCH from the env.
#   scripts/build.sh OUT
set -euo pipefail
cd "$(dirname "$0")/.."
GO="${GO:-go}"
GOOS= GOARCH= "$GO" generate .  # generator runs on the host, not the target
# nethttpomithttp2: drops net/http's bundled HTTP/2 (−0.55 MB). WebSockets are
# HTTP/1.1 regardless; behind nginx the browser still gets h2 from nginx.
CGO_ENABLED=0 "$GO" build -trimpath -tags nethttpomithttp2 -ldflags='-s -w' -o "$1" .
