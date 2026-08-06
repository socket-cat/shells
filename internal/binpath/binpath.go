// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package binpath provides a cached list of available commands (from compgen
// or PATH scanning) used by the /api/which endpoint for tab-completion.
package binpath

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"shells/internal/util"
)

const (
	cacheTTL   = 5 * time.Minute
	maxResults = 100
)

var (
	mu          sync.RWMutex
	binaries    []string
	lastRefresh time.Time
)

// Init loads the initial binary list and starts a background refresh goroutine.
func Init() {
	refresh()
	go func() {
		for {
			time.Sleep(cacheTTL / 2)
			refresh()
		}
	}()
}

func refresh() {
	list, err := compgen()
	if err != nil {
		list = scanPath()
	}
	sort.Strings(list)
	list = dedup(list)

	mu.Lock()
	binaries = list
	lastRefresh = time.Now()
	mu.Unlock()
}

func compgen() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// bash -i sources ~/.bashrc, where interactive PATH additions (e.g.
	// npm-global) live; bash -l (login) skips ~/.bashrc entirely, so compgen
	// under -l misses user binaries like cline. -i with -c emits no prompt,
	// and stderr job-control notices are silenced.
	cmd := exec.CommandContext(ctx, "bash", "-i", "-c", "compgen -c")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

func scanPath() []string {
	path := os.Getenv("PATH")
	dirs := strings.Split(path, ":")
	seen := make(map[string]bool)
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.Mode()&0o111 != 0 {
				seen[entry.Name()] = true
			}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	return result
}

func dedup(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Search returns up to maxResults command names starting with prefix.
func Search(prefix string) []string {
	if prefix == "" {
		return nil
	}
	mu.RLock()
	list := make([]string, len(binaries))
	copy(list, binaries)
	mu.RUnlock()
	return util.PrefixSearch(list, prefix, maxResults)
}
