// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// connectTTY relays this terminal to a remote session, like `ssh -t host`:
// the tty raw, keys in, output out, SIGWINCH → resize. With no sid it opens
// a session of its own (shells connect <name>); with one it attaches to the
// session ssh.Spawn opened for a local PTY.
func connectTTY(keysDir, id, sid, marker string, sigs <-chan os.Signal) (int, error) {
	r, err := load(keysDir, id)
	if err != nil {
		return 0, err
	}
	c, err := connect(r, sid == "") // a new session: open is an /api call
	if err != nil {
		return 0, err
	}
	defer c.close()
	if sid == "" {
		cols, rows := ttySize()
		if sid, err = c.open(cols, rows, "", ""); err != nil {
			return 0, err
		}
	} else if sidBytes(sid) == nil {
		return 0, fmt.Errorf("invalid session id %q", sid)
	}
	restore, err := rawTTY()
	if err != nil {
		c.deleteSession(sid)
		return 0, err
	}
	defer restore()
	return c.relay(sid, marker, os.Stdin, os.Stdout, sigs, true)
}

func stty(args ...string) ([]byte, error) {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = os.Stdin
	return cmd.Output()
}

// ttySize is the terminal's size ("rows cols" from stty), 80×24 when it
// has none. Not fmt.Sscan: it would link fmt's scanner (18 KB) for this.
func ttySize() (cols, rows int) {
	out, _ := stty("size")
	if f := strings.Fields(string(out)); len(f) == 2 {
		rows, _ = strconv.Atoi(f[0])
		cols, _ = strconv.Atoi(f[1])
	}
	if cols < 1 || rows < 1 {
		return 80, 24
	}
	return cols, rows
}

// rawTTY puts the terminal in raw mode, as ssh -t does, and returns what
// restores it.
func rawTTY() (func(), error) {
	state, err := stty("-g")
	if err != nil {
		return nil, errors.New("shells connect needs a terminal")
	}
	if _, err := stty("raw", "-echo"); err != nil {
		return nil, err
	}
	return func() { _, _ = stty(strings.TrimSpace(string(state))) }, nil
}
