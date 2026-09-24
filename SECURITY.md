# Security Policy

Shells — persistent web terminal / SSH gateway. Pure Go stdlib server,
AGPL-3.0-or-later. Shipped as static binaries for Linux, macOS, FreeBSD
(amd64/arm64) via GitHub releases and socket.cat.

## Supported versions

Only the **latest tagged release** is supported.

Security-support window: each minor version receives security fixes until the
next minor ships, plus **90 days** after that ship date. Patch releases within
a minor carry the same fixes; there is no backport stream to older minors.

## Reporting a vulnerability

**Private channel only:** GitHub private vulnerability reporting —
<https://github.com/socket-cat/shells/security/advisories/new> (Security tab →
"Report a vulnerability"). Do **not** open a public issue for a security
report.

Targets: **72 h** to a triage acknowledgement, **14 days** to a fix for
exploitable vulnerabilities. If a fix slips, you get a status update at the
14-day mark, not silence.

## Handling process

1. **Register** — the report becomes an `NC-*` entry in the project's
   nonconformity register (internal dev workspace; closed findings are kept,
   never deleted).
2. **Fix behind a test** — behavior changes ship with a test that fails on the
   vulnerable code.
3. **Security-review the diff** — crypto/TLS, auth, input parsing, file paths,
   network listeners go through a security review of the change diff only.
4. **Coordinated disclosure** — the fix ships in the next release; the release
   notes credit the reporter and describe the vulnerability after the fixed
   binaries are published.

## Scope

Covers the **shipped binaries** (GitHub releases + socket.cat). Self-hosted
operators own their deployment controls — TLS termination, reverse proxy,
firewall allow-list, secret hygiene — the standard vendor-supplies-code /
operator-runs-environment split. Hardening checklist for operators:
`README.md` "Get started".

## Security model (by design, not vulnerabilities)

Shells is a **single-user** tool: whoever holds the E2E secret is the owner
and already has a shell as the server user. Consequently:

- **Session access** — any authenticated client can attach to any session.
  Sessions are not scoped per client; run one instance per user.
- **Folder browsing** — `/api/ls` lists any directory the server user can
  read. It is not sandboxed, because the folder picker has to see everything
  the shell can reach anyway.
- **Secrets in memory** — key material is zeroed where Go allows it. Copies
  held inside the Go standard library (e.g. TLS/AES state) cannot be zeroed.
  This is a platform limitation.

## Cyber Resilience Act

Manufacturer duties under Regulation (EU) 2024/2847 are addressed from the
next release (v-next); the readiness inventory is maintained in the project's
private dev workspace. Vulnerability reporting to ENISA/CSIRT per Art. 14
applies when a vulnerability in the distributed product is actively exploited.
