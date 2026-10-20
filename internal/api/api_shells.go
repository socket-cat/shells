// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Shells remotes in the SSH endpoints: the picker sends a url where it sends
// user@host, and a connection of kind "shells" answers ls / which from the
// remote's own /api, where an ssh one runs a script over ssh.
package api

import (
	"errors"
	"net/http"

	"shells/internal/federate"
	"shells/internal/ssh"
	"shells/internal/util"
)

// handleShellsProbe: reachable as a shells remote → the picker asks for the
// secret (keyReady false), as ssh-probe makes it ask for a password. A
// socket.cat name first answers pair: the code to approve on socket.cat.
func (h *Handler) handleShellsProbe(w http.ResponseWriter, rawURL string) {
	err := federate.Probe(rawURL)
	var pair *federate.PairError
	if errors.As(err, &pair) {
		util.SendJSON(w, 200, map[string]any{"pair": map[string]string{"code": pair.Code, "url": pair.URL}}, nil)
		return
	}
	if err != nil {
		util.SendJSON(w, 200, map[string]any{"unreachable": true, "error": err.Error()}, nil)
		return
	}
	util.SendJSON(w, 200, map[string]any{"keyReady": false}, nil)
}

// handleShellsSetup is ssh-setup with the remote's secret in the password
// field: it is used once and only its hash is stored.
func (h *Handler) handleShellsSetup(w http.ResponseWriter, rawURL, secret string) {
	if secret == "" {
		util.SendJSON(w, 200, map[string]any{"error": "Secret required"}, nil)
		return
	}
	c, err := h.sshMgr.SetupShells(rawURL, []byte(secret))
	if err != nil {
		code := "unknown"
		if errors.Is(err, federate.ErrWrongSecret) {
			code = "wrong_secret"
		}
		util.SendJSON(w, 200, map[string]any{"error": err.Error(), "code": code}, nil)
		return
	}
	util.SendJSON(w, 200, map[string]any{"id": c.ID, "kind": c.Kind, "host": c.Host, "port": c.Port, "hostname": c.Hostname, "keyReady": true}, nil)
}

// shellsForward answers ls / which for a shells connection from the remote's
// same endpoint; fallback is the empty reply ssh-ls / ssh-which give on error.
func (h *Handler) shellsForward(w http.ResponseWriter, conn *ssh.Connection, path string, body, fallback map[string]any) {
	out, err := federate.Call(h.cfg.SSHKeysDir, conn.ID, path, body)
	if err != nil {
		fallback["error"] = err.Error()
		util.SendJSON(w, 200, fallback, nil)
		return
	}
	util.SendJSON(w, 200, out, nil)
}
