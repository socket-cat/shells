// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package config

import "testing"

func TestEnvTrue(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"1", true},
		{"true", true},
		{"on", true},
		{"TRUE", true},
		{"On", true},
		{" on ", true},
		{"1 ", true},
		{"0", false},
		{"false", false},
		{"off", false},
		{"yes", false},
		{"garbage", false},
	}
	for _, tc := range cases {
		if got := EnvTrue(tc.in); got != tc.want {
			t.Errorf("EnvTrue(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
