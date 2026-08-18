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
SECRET=your-secret PORT=2222 ./shells
```

<p align="center"><img src="docs/demo.gif" alt="Shells demo — desktop and mobile" width="920"></p>

Open `http://localhost:2222` — the browser asks for the E2E secret; enter the
same `SECRET` you just set. Prebuilt for Linux, macOS and FreeBSD (amd64 +
arm64); [releases](https://github.com/socket-cat/shells/releases/latest) have
checksums and direct links. For production, put it behind a reverse proxy
with TLS (the PWA needs HTTPS).

## Why

- **Persistent sessions** — shells keep running when you close the tab or lock
  your phone; reattach from any device. Built for long-running jobs and AI CLI
  agents on the go.
- **One binary** — ~8 MB, fully static, cross-compiled. Drop it on any box.
- **Zero deps** — pure Go standard library, no `node_modules`, no native addons.
- **E2E encrypted** — P-256 ECDH → AES-256-GCM; keys never leave your device.
- **Mobile-first** — installable PWA, touch gestures, on-screen keyboard picker.
- **Rootless** — runs as your user, no sudo.

## Configure

| Variable | Default | What |
|---|---|---|
| `PORT` | `2222` | Listen port |
| `SECRET` | random | E2E shared secret — **set this** |
| `MAX_SESSIONS` | `200` | Max concurrent shells |
| `SHELLS_CWD` | `~` | Default working directory |
| `SHELLS_DEFAULT_SHELL` | auto-detected | Shell binary to spawn |
| `SHELLS_KEY_DIR` | `~/.socket.cat/config/shells` | Keys + state directory |
| `SHELLS_TLS` | `off` | Self-signed HTTPS (`wss://`, secure cookies) |
| `SHELLS_UPDATE_CHECK` | `true` | Self-update check (opt-out) |

## Build from source

Requires Go 1.24+. Most users don't need this — grab the prebuilt binary above.

```bash
CGO_ENABLED=0 go build -ldflags='-s -w' -o shells .
```

Cross-compile: set `GOOS`/`GOARCH` (linux/darwin/freebsd × amd64/arm64).
Go stdlib backend; vanilla JS + xterm.js frontend, embedded at build time.

## License

[AGPL-3.0](LICENSE)

---

*AES-GCM all the way — [socket.cat](https://socket.cat)*
