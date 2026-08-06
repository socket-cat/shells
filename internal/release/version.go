// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package release

import (
	"fmt"
	"strconv"
	"strings"
)

// parseVersion strictly parses "v1.2.3" or "1.2.3" into three parts.
func parseVersion(s string) (int, int, int, error) {
	v := s
	if strings.HasPrefix(v, "v") {
		v = v[1:]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("bad version %q", s)
	}
	var nums [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || strconv.Itoa(n) != p {
			return 0, 0, 0, fmt.Errorf("bad version %q", s)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], nil
}

// versionLess reports whether a < b, comparing numerically.
func versionLess(a, b string) (bool, error) {
	am, amn, amr, err := parseVersion(a)
	if err != nil {
		return false, err
	}
	bm, bmn, bmr, err := parseVersion(b)
	if err != nil {
		return false, err
	}
	if am != bm {
		return am < bm, nil
	}
	if amn != bmn {
		return amn < bmn, nil
	}
	return amr < bmr, nil
}
