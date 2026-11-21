// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shells/internal/config"
	"shells/internal/session"
)

func TestHandlePasteImageLocal(t *testing.T) {
	cfg := &config.Config{
		MaxSessions:     10,
		DefaultShell:    "/bin/sh",
		OutputBufferMax: 1000,
	}
	mgr, err := session.New(cfg)
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}
	h := New(cfg, mgr, nil, nil, nil)

	// Valid 1x1 PNG base64
	pngB64 := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPj/HwADBwEB4q+k8QAAAABJRU5ErkJggg=="

	sess, err := mgr.Create(80, 24, "/bin/sh", "/tmp", nil)
	if err != nil {
		t.Fatalf("mgr.Create: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/paste-image", nil)
	body := map[string]any{
		"image":     "data:image/png;base64," + pngB64,
		"sessionId": sess.ID,
	}

	h.handlePasteImage(w, r, body)

	if w.Code != 200 {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	respStr := w.Body.String()
	if !strings.Contains(respStr, `"/tmp/s-`) {
		t.Fatalf("expected /tmp/s- in response, got %s", respStr)
	}

	// Extract path from JSON
	var path string
	for _, part := range strings.Split(respStr, `"`) {
		if strings.HasPrefix(part, "/tmp/s-") {
			path = part
			break
		}
	}
	if path == "" {
		t.Fatalf("could not extract path from response %s", respStr)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file does not exist on disk: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("expected file mode 0600, got %o", mode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("dir stat failed: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0700 {
		t.Fatalf("expected dir mode 0700, got %o", mode)
	}

	// Verify exact file content matches original raw PNG bytes
	savedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}
	rawExpected, _ := base64.StdEncoding.DecodeString(pngB64)
	if string(savedBytes) != string(rawExpected) {
		t.Fatalf("saved file bytes do not match expected PNG payload")
	}

	// Verify session destruction cleans up the file
	mgr.Destroy(sess.ID)
	// Give onDestroy a moment to run
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		_ = os.Remove(path)
		t.Fatalf("expected file to be unlinked after session destroy, but it still exists")
	}
}

func TestHandlePasteImageRejectsInvalid(t *testing.T) {
	cfg := &config.Config{OutputBufferMax: 1000}
	h := New(cfg, nil, nil, nil, nil)

	// URL fetch of a non-image is rejected (uploads may be any type, URLs may
	// not); the test server is on loopback, so the guarded client is swapped
	// for this check only.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello plain text"))
	}))
	defer srv.Close()
	guarded := pasteHTTPClient
	pasteHTTPClient = srv.Client()
	t.Cleanup(func() { pasteHTTPClient = guarded })
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/paste-image", nil)
	h.handlePasteImage(w, r, map[string]any{"url": srv.URL})
	pasteHTTPClient = guarded
	if !strings.Contains(w.Body.String(), "unsupported image format") {
		t.Fatalf("expected unsupported image format error, got %s", w.Body.String())
	}

	// Empty body
	w2 := httptest.NewRecorder()
	h.handlePasteImage(w2, r, map[string]any{})
	if !strings.Contains(w2.Body.String(), "empty image") {
		t.Fatalf("expected empty image error, got %s", w2.Body.String())
	}

	// SSRF: the host itself, cloud metadata, and metadata spelled as an
	// IPv4-mapped IPv6 literal (which a substring check let through) are all
	// refused at dial time.
	for _, u := range []string{srv.URL, "http://169.254.169.254/latest/meta-data", "http://[::ffff:a9fe:a9fe]/latest/meta-data"} {
		w3 := httptest.NewRecorder()
		h.handlePasteImage(w3, r, map[string]any{"url": u})
		if !strings.Contains(w3.Body.String(), "prohibited image url host") {
			t.Fatalf("%s: expected prohibited image url host error, got %s", u, w3.Body.String())
		}
	}
}

func TestEvictOldest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "paste-evict-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create 5 files with staggered timestamps
	for i := 0; i < 5; i++ {
		p := filepath.Join(tmpDir, string(rune('a'+i))+".png")
		if err := os.WriteFile(p, []byte("testdata"), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Subtest 1: under budget -> no eviction
	evictOldest(tmpDir, 100)
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 files, got %d", len(entries))
	}

	// Subtest 2: incoming bytes exceed maxPasteDirBytes (50MB) -> evicts oldest files first
	evictOldest(tmpDir, maxPasteDirBytes)
	entriesAfter, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	// With incomingBytes == maxPasteDirBytes, totalSize must be 0 to fit, so all are evicted
	if len(entriesAfter) != 0 {
		t.Fatalf("expected 0 files after eviction exceeding budget, got %d", len(entriesAfter))
	}
}

func TestHandlePasteAnyFile(t *testing.T) {
	h := New(&config.Config{OutputBufferMax: 1000}, nil, nil, nil, nil)
	for name, want := range map[string]string{
		"report.XLSX":    ".xlsx",
		"../../x.sh;rm":  "",
		"a.toolongext12": "",
		"":               "",
	} {
		w := httptest.NewRecorder()
		h.handlePasteImage(w, httptest.NewRequest("POST", "/api/paste-image", nil), map[string]any{
			"image": base64.StdEncoding.EncodeToString([]byte("PK\x03\x04 not an image")),
			"name":  name,
		})
		var resp struct{ Path, Error string }
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Path == "" || filepath.Dir(resp.Path) != pasteDir() || filepath.Ext(resp.Path) != want {
			t.Fatalf("name %q: want ext %q in %s, got %s", name, want, pasteDir(), w.Body.String())
		}
		_ = os.Remove(resp.Path)
	}
}

func TestSecurePasteDir(t *testing.T) {
	base := t.TempDir()
	good := filepath.Join(base, "good")
	_ = os.Mkdir(good, 0777)
	if err := securePasteDir(good); err != nil {
		t.Fatalf("own dir should be accepted (and tightened): %v", err)
	}
	link := filepath.Join(base, "link")
	_ = os.Symlink(good, link)
	if securePasteDir(link) == nil {
		t.Fatal("symlinked dir must be refused")
	}
	file := filepath.Join(base, "file")
	_ = os.WriteFile(file, nil, 0600)
	if securePasteDir(file) == nil {
		t.Fatal("non-dir must be refused")
	}
}

// TestPublicIP: what a pasted image URL may resolve to. local stands for
// this host's interfaces: a public /24 and a public IPv6 /64.
func TestPublicIP(t *testing.T) {
	local := []net.Addr{
		&net.IPNet{IP: net.ParseIP("203.0.113.5"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8:1:2::5"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("2001:db8:7:7::5"), Mask: net.CIDRMask(128, 128)}, // DHCPv6
	}
	for _, c := range []struct {
		ip string
		ok bool
	}{
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"2001:db8:9::1", true},    // public, not on-link
		{"64:ff9b::808:808", true}, // NAT64 to a public IPv4
		{"2002:808:808::1", true},  // 6to4 from a public IPv4
		{"203.0.113.5", false},     // the host's own address
		{"203.0.113.77", false},    // an on-link neighbour
		{"2001:db8:1:2::1", false}, // a neighbour in the host's /64
		{"2001:db8:7:7::1", false}, // a neighbour in a DHCPv6 /128's /64
		{"2001:db8:7:8::1", true},  // the next /64 over
		{"127.0.0.1", false},
		{"::1", false},
		{"10.0.0.1", false},
		{"fd00::1", false},
		{"169.254.169.254", false},
		{"::ffff:169.254.169.254", false},
		{"fe80::1%eth0", false},
		{"0.1.2.3", false},
		{"100.64.0.1", false},
		{"192.0.0.8", false},
		{"198.18.0.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"::ffff:0:a9fe:a9fe", false},             // SIIT
		{"2001:0:4136:e378::1", false},            // Teredo
		{"64:ff9b::a00:5", false},                 // NAT64 to 10.0.0.5
		{"64:ff9b:1::a9fe:a9fe", false},           // local NAT64 to metadata
		{"64:ff9b:1::808:808", false},             // local NAT64: denied whole
		{"64:ff9b:1:a9fe:a9:fe00:808:808", false}, // /48 layout to metadata, /96 suffix public
		{"2002:a00:1::1", false},                  // 6to4 from 10.0.0.1
	} {
		if got := publicIP(netip.MustParseAddr(c.ip), local); got != c.ok {
			t.Errorf("publicIP(%s) = %v, want %v", c.ip, got, c.ok)
		}
	}
	// This box's own interface addresses are refused at dial time.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if err := publicOnly("tcp", net.JoinHostPort(n.IP.String(), "80"), nil); !errors.Is(err, errPrivateHost) {
				t.Errorf("own address %s: %v", n.IP, err)
			}
		}
	}
}
