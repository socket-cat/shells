// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package util

import (
	"sync"
	"time"
)

// RateLimiter implements a per-key sliding-window admission limiter with
// bounded memory. Each key keeps at most `limit` timestamps — rejected
// attempts are NOT recorded, so a flood cannot grow an entry past limit —
// and keys idle past the longest window in use are swept at most once a
// minute (the caller's own window would cut a longer limit's history short).
type RateLimiter struct {
	mu        sync.Mutex
	limits    map[string][]time.Time
	lastSweep time.Time
	maxWindow time.Duration
}

// NewRateLimiter creates an empty RateLimiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{limits: make(map[string][]time.Time)}
}

// Allow records one attempt under key and reports whether it is admitted:
// true as long as fewer than limit recorded attempts fall inside the sliding
// window; false afterwards, without recording the rejected attempt.
func (rl *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	rl.maxWindow = max(rl.maxWindow, window)
	if now.Sub(rl.lastSweep) > time.Minute {
		rl.lastSweep = now
		stale := now.Add(-rl.maxWindow)
		for k, ts := range rl.limits {
			keep := false
			for _, t := range ts {
				if t.After(stale) {
					keep = true
					break
				}
			}
			if !keep {
				delete(rl.limits, k)
			}
		}
	}
	var valid []time.Time
	for _, t := range rl.limits[key] {
		if len(valid) >= limit {
			break
		}
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	admit := len(valid) < limit
	if admit {
		valid = append(valid, now)
	}
	rl.limits[key] = valid
	return admit
}
