// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// SSH backend REST endpoints: stored-connection CRUD, probe, key setup,
// remote ls/which. Extracted from api.go.
package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"shells/internal/ssh"
	"shells/internal/util"
)

// --- SSH endpoints ---

func (h *Handler) handleSSHConnections(w http.ResponseWriter, r *http.Request, body map[string]any, method string) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available on server"}, nil)
		return
	}
	if method == "GET" || body["connections"] == nil {
		conns := h.sshMgr.All()
		util.SendJSON(w, 200, conns, nil)
		return
	}
	if !h.rateAllow("ssh-connections-"+h.clientIP(r), 10, time.Minute) {
		util.SendJSON(w, 429, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	rawConns, ok := body["connections"].([]any)
	if !ok {
		util.SendJSON(w, 200, map[string]any{"error": "Invalid connections data"}, nil)
		return
	}
	for _, raw := range rawConns {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, _ := c["id"].(string)
		host, _ := c["host"].(string)
		user, _ := c["user"].(string)
		port := util.IntFromAny(c["port"])
		hasOurKey, _ := c["hasOurKey"].(bool)
		hostname, _ := c["hostname"].(string)
		if ssh.ValidateConnectionID(id) != nil {
			continue
		}
		if ssh.ValidateParams(host, user, port) != nil {
			continue
		}
		_ = h.sshMgr.Add(ssh.Connection{ID: id, Host: host, User: user, Port: port, HasOurKey: hasOurKey, Hostname: hostname})
	}
	util.SendJSON(w, 200, map[string]any{"success": true}, nil)
}

func (h *Handler) handleSSHConnectionDelete(w http.ResponseWriter, path string) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available on server"}, nil)
		return
	}
	id := strings.TrimPrefix(path, "/api/ssh-connections/")
	if ssh.ValidateConnectionID(id) != nil {
		util.SendJSON(w, 200, map[string]any{"error": "Invalid connection ID"}, nil)
		return
	}
	conn := h.sshMgr.FindByID(id)
	if conn == nil {
		util.SendJSON(w, 200, map[string]any{"error": "Connection not found"}, nil)
		return
	}

	remoteKeyRemoved := false
	var remoteKeyError string
	if conn.HasOurKey {
		cleaned, reason := h.sshMgr.RemoveRemoteKey(id, conn.Host, conn.User, conn.Port)
		remoteKeyRemoved = cleaned
		if !cleaned {
			remoteKeyError = reason
		}
	}

	h.sshMgr.Delete(id)
	h.sshMgr.InvalidateRemoteCache(id)

	resp := map[string]any{"removed": true}
	if conn.HasOurKey {
		resp["remoteKeyRemoved"] = remoteKeyRemoved
		if remoteKeyError != "" {
			resp["remoteKeyError"] = remoteKeyError
		}
	}
	util.SendJSON(w, 200, resp, nil)
}

func (h *Handler) handleSSHProbe(w http.ResponseWriter, body map[string]any, r *http.Request) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available on server"}, nil)
		return
	}
	if !h.rateAllow("ssh-probe-"+h.clientIP(r), 10, time.Minute) {
		util.SendJSON(w, 200, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	host, _ := body["host"].(string)
	user, _ := body["user"].(string)
	port := 22
	if p, ok := body["port"].(float64); ok {
		port = int(p)
	}
	if err := ssh.ValidateParams(host, user, port); err != nil {
		util.SendJSON(w, 200, map[string]any{"error": err.Error()}, nil)
		return
	}

	result, err := h.sshMgr.Probe(host, user, port)
	if err != nil {
		util.SendJSON(w, 200, map[string]any{"error": "Probe failed"}, nil)
		return
	}
	util.SendJSON(w, 200, result, nil)
}

func (h *Handler) handleSSHSetup(w http.ResponseWriter, body map[string]any, r *http.Request) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available on server"}, nil)
		return
	}

	ip := h.clientIP(r)
	if !h.rateAllow("ssh-setup-"+ip, 10, time.Minute) {
		util.SendJSON(w, 200, map[string]any{"error": "Too many setup attempts", "code": "rate_limited"}, nil)
		return
	}

	host, _ := body["host"].(string)
	user, _ := body["user"].(string)
	port := 22
	if p, ok := body["port"].(float64); ok {
		port = int(p)
	}
	password, _ := body["password"].(string)
	if err := ssh.ValidateParams(host, user, port); err != nil {
		util.SendJSON(w, 200, map[string]any{"error": err.Error()}, nil)
		return
	}
	if password == "" {
		util.SendJSON(w, 200, map[string]any{"error": "Password required"}, nil)
		return
	}

	var connID string
	if conn := h.sshMgr.FindByHostUser(host, user, port); conn != nil {
		connID = conn.ID
	}
	if connID == "" {
		connID = util.NewUUID()
	}

	err := h.sshMgr.SetupKey(connID, host, user, port, password)
	if err != nil {
		var se *ssh.SetupError
		if errors.As(err, &se) {
			util.SendJSON(w, 200, map[string]any{"error": se.Msg, "code": se.Code}, nil)
		} else {
			util.SendJSON(w, 200, map[string]any{"error": "SSH setup failed", "code": "unknown"}, nil)
		}
		return
	}

	hostname, ok := h.sshMgr.ProbeWithKey(connID, host, user, port)
	if !ok {
		util.SendJSON(w, 200, map[string]any{"error": "Key installed but verification failed", "code": "verify_failed"}, nil)
		return
	}

	_ = h.sshMgr.Add(ssh.Connection{ID: connID, Host: host, User: user, Port: port, HasOurKey: true, Hostname: hostname})
	util.SendJSON(w, 200, map[string]any{"id": connID, "hostname": hostname, "keyReady": true, "hasOurKey": true}, nil)
}

func (h *Handler) handleSSHLs(w http.ResponseWriter, body map[string]any, r *http.Request) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available"}, nil)
		return
	}
	if !h.rateAllow("ssh-ls-"+h.clientIP(r), 10, time.Minute) {
		util.SendJSON(w, 200, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	connID, _ := body["connectionId"].(string)
	remotePath, _ := body["path"].(string)
	if connID == "" {
		util.SendJSON(w, 200, map[string]any{"error": "connectionId required"}, nil)
		return
	}

	conn := h.sshMgr.FindByID(connID)
	if conn == nil {
		util.SendJSON(w, 200, map[string]any{"error": "Connection not found"}, nil)
		return
	}

	folders, err := h.sshMgr.ListRemote(connID, conn.Host, conn.User, conn.Port, remotePath)
	if err != nil {
		util.SendJSON(w, 200, map[string]any{"error": err.Error(), "folders": []string{}}, nil)
		return
	}
	parent := "/"
	if remotePath != "/" && remotePath != "" {
		trimmed := strings.TrimRight(remotePath, "/")
		idx := strings.LastIndex(trimmed, "/")
		if idx > 0 {
			parent = trimmed[:idx]
		}
	}
	util.SendJSON(w, 200, map[string]any{"path": remotePath, "parent": parent, "folders": folders}, nil)
}

func (h *Handler) handleSSHWhich(w http.ResponseWriter, body map[string]any, r *http.Request) {
	if !h.cfg.SSHAvailable {
		util.SendJSON(w, 200, map[string]any{"error": "SSH not available"}, nil)
		return
	}
	if !h.rateAllow("ssh-which-"+h.clientIP(r), 10, time.Minute) {
		util.SendJSON(w, 200, map[string]any{"error": "Rate limit exceeded"}, nil)
		return
	}
	connID, _ := body["connectionId"].(string)
	q, _ := body["q"].(string)
	if connID == "" {
		util.SendJSON(w, 200, map[string]any{"error": "connectionId required"}, nil)
		return
	}

	conn := h.sshMgr.FindByID(connID)
	if conn == nil {
		util.SendJSON(w, 200, map[string]any{"error": "Connection not found"}, nil)
		return
	}

	matches, err := h.sshMgr.SearchRemoteBinaries(connID, conn.Host, conn.User, conn.Port, q)
	if err != nil {
		util.SendJSON(w, 200, map[string]any{"matches": []string{}}, nil)
		return
	}
	util.SendJSON(w, 200, map[string]any{"matches": matches}, nil)
}
