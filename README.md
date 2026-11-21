# Shells

Persistent web terminal — tmux for the browser, phone to desktop.
End-to-end encrypted, zero-trust.

[![AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Version](https://img.shields.io/github/v/release/socket-cat/shells)](https://github.com/socket-cat/shells/releases)

---

## Quick launch

```bash
curl -s https://socket.cat/start.php?shells | bash
```

Connects the machine you run it on to your socket.cat account — its shells
then appear in your dashboard.

## Get started (self-hosted)

```bash
curl -fsSL "https://github.com/socket-cat/shells/releases/latest/download/shells-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" -o shells
chmod +x shells
SHELLS_SECRET=your-secret ./shells
```

<p align="center"><img src="docs/demo.gif" alt="Shells demo — desktop and mobile" width="920"></p>

Open `http://localhost:2222` and enter the `SHELLS_SECRET` you just set.

- **From another machine or Docker:** start it with `SHELLS_HOST=0.0.0.0` and
  open `<host>:2222`. It switches to HTTPS on its own; accept the self-signed
  certificate once.
- **No certificate warning, installable PWA:** put it behind a reverse proxy
  with TLS.

Prebuilt for Linux, macOS and FreeBSD (amd64 + arm64);
[releases](https://github.com/socket-cat/shells/releases/latest) have
checksums and direct links.

## Why

- **Persistent sessions** — shells keep running when you close the tab or lock
  your phone; reattach from any device. Built for long-running jobs and AI CLI
  agents on the go.
- **Other machines over SSH** — type `user@host[:port]` in the new-session
  picker and enter the password once; a per-host key is installed and its
  shells, folders and commands sit beside the local ones.
- **Files straight to the shell** — paste (Ctrl+V), drop or attach any file up
  to 10 MB, even over SSH; it lands on the host and its path appears on the
  prompt, ready for your AI CLI agent. On mobile, the attach button takes a
  photo or picks files.
- **One binary** — ~8 MB, fully static, cross-compiled. Drop it on any box.
- **Zero deps** — pure Go standard library, no `node_modules`, no native addons.
- **E2E encrypted** — P-256 ECDH → AES-256-GCM; keys never leave your device.
- **Signed self-update** — releases verified against an Ed25519 signature
  served from socket.cat, not GitHub; a tampered release never installs.
- **Mobile-first** — installable PWA, touch gestures, on-screen keyboard picker.
- **Rootless** — runs as your user, no sudo.

## Reach another shells

One shells can open sessions on another, with no SSH between them. In the
new-session picker type the other one's `https://host[:port]` where you
would type `user@host`, then its secret. From then on it works like an SSH
host: its folders, commands and sessions in this UI. From a terminal, call
it by its hostname:

```bash
shells exec dev-box -- 'cd /srv/x && git status'   # exit code kept
shells connect dev-box                             # interactive
```

The remote needs only HTTPS: its own (on by default once `SHELLS_HOST` is
not loopback) or a TLS proxy. Its identity is pinned on first use, and only
a hash of its secret is stored. `exec` keeps stdout and stderr apart and
passes stdin byte for byte, like `ssh host cmd`.

## Configure

| Variable | Default | What |
|---|---|---|
| `SHELLS_HOST` | `127.0.0.1` | Listen address (`0.0.0.0` for all interfaces) |
| `SHELLS_PORT` | `2222` | Listen port (alias: `PORT`) |
| `SHELLS_SECRET` | random | E2E shared secret — **set this** (alias: `SECRET`) |
| `SHELLS_MAX_SESSIONS` | `200` | Max concurrent shells (alias: `MAX_SESSIONS`) |
| `SHELLS_LOG` | stdout/stderr | Log file path for supervisor & server (alias: `LOG`) |
| `SHELLS_CWD` | `~` | Default working directory |
| `SHELLS_DEFAULT_SHELL` | auto-detected | Shell binary to spawn |
| `SHELLS_KEY_DIR` | `~/.socket.cat/config/shells` | Keys + state directory |
| `SHELLS_TLS` | `on` unless `SHELLS_HOST` is loopback | Self-signed HTTPS on the same port as plain http |
| `SHELLS_TOKEN` | random | Admin bearer API token (`X-Shells-Token`) |
| `SHELLS_UPDATE_CHECK` | `true` | Self-update check (opt-out) |

## Build from source

Requires Go 1.26+. Most users don't need this — grab the prebuilt binary above.

```bash
scripts/build.sh shells
```

Cross-compile: set `GOOS`/`GOARCH` (linux/darwin/freebsd × amd64/arm64).
Go stdlib backend; vanilla JS + xterm.js frontend, embedded at build time.

## License

[AGPL-3.0](LICENSE). Provided as is, without warranty or support.

---

*AES-GCM all the way — [socket.cat](https://socket.cat)*
