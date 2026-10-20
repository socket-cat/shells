// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package federate

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"shells/internal/util"
)

// pairBase is the socket.cat that pairs: a socket.cat app name is behind the
// relay's GUC gate, so this server gets its own relay-only session there,
// approved by the owner in the browser (guc start.php ?pair / ?check /
// ?unpair). Tests and dev builds point it elsewhere (-ldflags -X).
var pairBase = "https://socket.cat"

// pairDomain: hosts under it are behind the relay's GUC gate.
var pairDomain = "socket.cat"

// PairError: the owner approves Code at URL, then the picker probes again.
type PairError struct{ Code, URL string }

func (e *PairError) Error() string { return "approve code " + e.Code + " at " + e.URL }

// pairing: per origin, the pending device (polled on each probe) or the
// approved session, until Setup stores it in <id>.shells. In memory: a
// restart in between costs a new code; the unused session expires in
// socket.cat's 7-day idle GC.
var pairing = struct {
	sync.Mutex
	m map[string]*pend
}{m: map[string]*pend{}}

type pend struct{ code, device, guc string }

func isSocketCat(host string) bool {
	return host == pairDomain || strings.HasSuffix(host, "."+pairDomain)
}

// No redirects: the SOCAT header (device or session id) would follow them.
var pairHTTP = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func pairCall(query, header string) (int, string, error) {
	req, err := http.NewRequest("GET", pairBase+"/start.php?"+query, nil)
	if err != nil {
		return 0, "", err
	}
	if header != "" {
		req.Header.Set("SOCAT", header)
	}
	resp, err := pairHTTP.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}

// relaySession returns the approved session for a socket.cat origin, or a
// PairError with the code to approve: a fresh one, or the pending one while
// socket.cat answers "wait".
func relaySession(origin string) (string, error) {
	pairing.Lock()
	defer pairing.Unlock()
	if p := pairing.m[origin]; p != nil {
		if p.guc != "" {
			return p.guc, nil
		}
		status, body, err := pairCall("check", p.device)
		switch {
		case err != nil:
			return "", err
		case status != 200:
			return "", fmt.Errorf("socket.cat answered %d: wait a minute and press Continue again", status)
		case body == "wait":
			return "", &PairError{p.code, pairBase + "/start.php?code=" + p.code}
		case body == "cancelled":
			delete(pairing.m, origin)
			return "", errors.New("the pairing was cancelled on socket.cat")
		case validSID(body):
			p.guc = body
			return body, nil
		}
		delete(pairing.m, origin) // gone: expired, mint a new code
	}
	status, body, err := pairCall("pair="+url.QueryEscape(origin), "")
	if err != nil {
		return "", err
	}
	code, device, ok := strings.Cut(body, " ")
	if status != 200 || !ok || !validSID(device) || len(code) != 9 {
		return "", fmt.Errorf("socket.cat refused the pairing (%d)", status)
	}
	pairing.m[origin] = &pend{code: code, device: device}
	return "", &PairError{code, pairBase + "/start.php?code=" + code}
}

// forgetPairing drops an origin's session once Setup stored it, or once the
// relay refused it.
func forgetPairing(origin string) {
	pairing.Lock()
	delete(pairing.m, origin)
	pairing.Unlock()
}

// Unpair ends the relay session of a connection being removed (best effort:
// an unused one also expires after 7 idle days).
func Unpair(keysDir, id string) {
	if r, err := load(keysDir, id); err == nil && validSID(r.GUC) {
		_, _, _ = pairCall("unpair", r.GUC)
	}
}

// validSID: a socket.cat session id (and device), 32 URL-safe base64 chars;
// it becomes a header value, so nothing else gets through.
func validSID(s string) bool {
	return len(s) == 32 && util.OnlyChars(s, util.Alnum+"-_")
}

// relayRefused: the relay answers 401 to a GUC it does not map (expired after
// 7 idle days, revoked, or never paired).
func relayRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "handshake refused: 401")
}
