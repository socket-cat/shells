// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package binpath

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"shells/internal/pty"
)

// TestCompgenInBackgroundJob: `shells &` from an interactive shell runs in a
// background process group of a terminal. bash -i opening that terminal
// would stop the whole group with SIGTTIN, and the server never serves.
func TestCompgenInBackgroundJob(t *testing.T) {
	if os.Getenv("BINPATH_BG_CHILD") == "1" {
		list, err := compgen()
		fmt.Printf("compgen-done n=%d err=%v\n", len(list), err)
		return
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// set -m: the job gets its own process group, in the background.
	script := fmt.Sprintf("set -m; BINPATH_BG_CHILD=1 %q -test.run '^TestCompgenInBackgroundJob$' & echo pid=$!; wait", exe)
	term, err := pty.Spawn("/bin/sh", []string{"-c", script}, os.Environ(), t.TempDir(), 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Kill()
	var mu sync.Mutex
	var out strings.Builder
	term.OnData(func(b []byte) { mu.Lock(); out.Write(b); mu.Unlock() })
	read := func() string { mu.Lock(); defer mu.Unlock(); return out.String() }
	// Past compgen's own 10 s bound: only a stopped job misses this.
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if strings.Contains(read(), "compgen-done") {
			return
		}
	}
	if m := regexp.MustCompile(`pid=(\d+)`).FindStringSubmatch(read()); m != nil {
		if pid, _ := strconv.Atoi(m[1]); pid > 0 {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}
	t.Fatalf("compgen stopped its background job (SIGTTIN); output: %q", read())
}
