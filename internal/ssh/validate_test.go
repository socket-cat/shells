// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package ssh

import (
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"shells/internal/branding"
	"shells/internal/util"
)

// TestValidatorsMatchRegexSpec pins the hand-written validators (which
// replaced regexp to keep the binary small) to the original regexes over
// hostile edge cases plus random strings from a trap-heavy alphabet.
func TestValidatorsMatchRegexSpec(t *testing.T) {
	var (
		hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
		hostRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.\-]*$`)
		ipRe       = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
		userRe     = regexp.MustCompile(`^[a-zA-Z0-9_.][a-zA-Z0-9_.\-]*$`)
		uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
		hexRe      = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
		verRe      = regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`)
	)
	check := func(s string) {
		if got, want := util.ValidHostname(s), s != "" && len(s) <= 253 && hostnameRE.MatchString(s); got != want {
			t.Errorf("ValidHostname(%q) = %v, want %v", s, got, want)
		}
		if got, want := validHost(s), s != "" && (hostRe.MatchString(s) || ipRe.MatchString(s)); got != want {
			t.Errorf("validHost(%q) = %v, want %v", s, got, want)
		}
		if got, want := len(s) <= 32 && ValidateParams("h", s, 22) == nil, len(s) <= 32 && userRe.MatchString(s); got != want {
			t.Errorf("user(%q) = %v, want %v", s, got, want)
		}
		if got, want := isUUID(s), uuidRe.MatchString(strings.ToLower(s)); got != want {
			t.Errorf("isUUID(%q) = %v, want %v", s, got, want)
		}
		if got, want := branding.ValidAccent(s), hexRe.MatchString(s); got != want {
			t.Errorf("ValidAccent(%q) = %v, want %v", s, got, want)
		}
		maj, mnr, ok := parseOpenSSHVersion(s)
		m := verRe.FindStringSubmatch(s)
		if ok != (m != nil) {
			t.Errorf("parseOpenSSHVersion(%q) ok=%v, want %v", s, ok, m != nil)
		} else if ok {
			wmaj, _ := strconv.Atoi(m[1])
			wmnr, _ := strconv.Atoi(m[2])
			if maj != wmaj || mnr != wmnr {
				t.Errorf("parseOpenSSHVersion(%q) = %d.%d, want %d.%d", s, maj, mnr, wmaj, wmnr)
			}
		}
	}
	for _, s := range []string{
		"", "a", "-", ".", "a-", "-a", "a.", "a..b", "1.2.3.4", "999.1.1.1", "1.2.3.4.",
		"host\n", "\nhost", "ho st", "ho\x00st", "hóst", "\xff", "K", "İ",
		"root", "a_b", "../etc", "a/b", "-Efile", "-", "a-b",
		"0123abcd-0123-0123-0123-0123456789ab", "0123ABCD-0123-0123-0123-0123456789AB",
		"0123abcd-0123-0123-0123-0123456789a", "0123abcd-0123-0123-0123-0123456789abc",
		"0123abcd_0123-0123-0123-0123456789ab", "0123abcg-0123-0123-0123-0123456789ab",
		"0123abcd-0123-0123-0123-0123456789a\n", "0123abcd-0123-0123-0123-0123456789aK",
		"#a1B2c3", "#a1B2c", "#a1B2c3d", "a1B2c3d", "##a1B2c", "#a1B2cg", "#a1b2c3\n",
		"OpenSSH_9.2p1 Debian", "OpenSSH_7.5", "OpenSSH_7.6", "OpenSSH_.1 OpenSSH_8.1",
		"OpenSSH_8", "OpenSSH_8.", "xOpenSSH_10.11y", "OpenSSH_OpenSSH_1.2",
	} {
		check(s)
	}
	const alpha = "aZ09-._#K\n\x00\xff/ OpenSSH_4.2fA"
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		b := make([]byte, r.IntN(40))
		for j := range b {
			b[j] = alpha[r.IntN(len(alpha))]
		}
		check(string(b))
	}
	// Random near-UUIDs: mutate one byte of a valid ID.
	for i := 0; i < 5000; i++ {
		b := []byte("0123abcd-0123-4567-89ab-cdefABCDEF01")
		b[r.IntN(len(b))] = alpha[r.IntN(len(alpha))]
		check(string(b))
	}
}
