# Security

Shells is free software published by one developer in their spare time,
under AGPL-3.0-or-later. It is provided **as is, with no warranty and no
support**: see sections 15 and 16 of the [LICENSE](LICENSE). There is no
support contract, no response time and no promise that any issue will be
fixed.

## Versions

Fixes, when there are any, go into the latest release only. Older versions
are never patched.

## Reporting a vulnerability

Use GitHub's private report form —
<https://github.com/socket-cat/shells/security/advisories/new> (Security tab →
"Report a vulnerability") — so details stay out of public issues. Reports
are read when time allows; no acknowledgement or fix date is promised.

## You run it, you secure it

Shells gives whoever holds the secret a shell on your machine. Where you
expose it, who gets the secret and how the host is protected are your
decisions and your responsibility.

## Security model (by design, not vulnerabilities)

Shells is a **single-user** tool: whoever holds the E2E secret is the owner
and already has a shell as the server user. Consequently:

- **Session access** — any authenticated client can attach to any session.
  Sessions are not scoped per client; run one instance per user.
- **Folder browsing** — `/api/ls` lists any directory the server user can
  read. It is not sandboxed, because the folder picker has to see everything
  the shell can reach anyway.
- **File paste / drop** — uploaded files (any type, max 10 MB) are written to
  `/tmp/s-<uid>` (dir 0700, refused if not owned by the server user; files
  0600, random names), evicted oldest-first past 50 files / 50 MB, and
  deleted when the session closes. On SSH sessions they go to `/tmp/s-<user>` on
  the remote host.
- **Secrets in memory** — key material is zeroed where Go allows it. Copies
  held inside the Go standard library (e.g. TLS/AES state) cannot be zeroed.
  This is a platform limitation.
