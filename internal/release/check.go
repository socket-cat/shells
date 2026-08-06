// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

package release

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	maxManifestSize = 1 << 20   // 1MB checksums file cap
	maxSigSize      = 1 << 12   // 4KB signature cap
	maxBinarySize   = 128 << 20 // 128MB binary cap (decompressed stream)
)

var errNoUpdate = errors.New("no newer version")

// ErrVerificationFailed marks a cryptographic integrity failure — the socket.cat
// signature did not verify over GitHub's checksums (or the signed version is
// inconsistent with the release). This is the supply-chain alarm: a benign
// network/status failure must never be confused with it.
var ErrVerificationFailed = errors.New("release: signature verification failed")

// Config carries everything the check needs. Platform is the asset basename
// (e.g. "shells-linux-amd64").
type Config struct {
	Version      string
	Repo         string
	APIBase      string
	SigURL       string
	ChecksumsURL string
	DownloadBase string
	Platform     string
	UserAgent    string
	UpdateCheck  bool
	BinaryPath   string
}

// Info is the result shape returned to clients. Errors are fail-closed: the
// attacker-influenced tag is never echoed back on failure. VerificationFailed
// flags the supply-chain alarm (signature/integrity mismatch) — distinct from
// a benign transient failure.
type Info struct {
	UpdateAvailable    bool   `json:"updateAvailable"`
	CurrentVersion     string `json:"currentVersion"`
	LatestVersion      string `json:"latest,omitempty"`
	ChecksumVerified   bool   `json:"checksumVerified"`
	SignatureVerified  bool   `json:"signatureVerified"`
	SignedBy           string `json:"signedBy,omitempty"`
	VerificationFailed bool   `json:"verificationFailed,omitempty"`
	Error              string `json:"error,omitempty"`
}

type manifest struct {
	version  string
	digests  map[string]string
	signedBy string
}

// CheckLatest runs the light verification: GitHub tag + signed checksums
// manifest. It never downloads the binary.
func CheckLatest(ctx context.Context, cfg Config) *Info {
	info := &Info{
		CurrentVersion: cfg.Version,
	}
	if !cfg.UpdateCheck {
		info.Error = "update checks disabled"
		return info
	}
	m, err := fetchManifest(ctx, cfg)
	if err != nil {
		if errors.Is(err, errNoUpdate) {
			return info
		}
		if errors.Is(err, ErrVerificationFailed) {
			info.VerificationFailed = true
			info.Error = "update verification failed — signature mismatch (possible tampering)"
			return info
		}
		info.Error = "update check failed"
		return info
	}
	info.UpdateAvailable = true
	info.LatestVersion = m.version
	info.ChecksumVerified = true
	info.SignatureVerified = true
	info.SignedBy = m.signedBy
	return info
}

// Apply downloads and sha256-verifies the binary for cfg.Platform against the
// signed manifest, writing it to cfg.BinaryPath+".new" (chmod +x). It returns
// the verified version.
func Apply(ctx context.Context, cfg Config) (string, error) {
	if !cfg.UpdateCheck {
		return "", errors.New("update checks disabled")
	}
	if cfg.BinaryPath == "" {
		return "", errors.New("binary path unknown")
	}
	m, err := fetchManifest(ctx, cfg)
	if err != nil {
		return "", err
	}
	wantHex, ok := m.digests[cfg.Platform]
	if !ok {
		return "", fmt.Errorf("no signed digest for %s", cfg.Platform)
	}
	url := strings.TrimSuffix(cfg.DownloadBase, "/") + "/" + cfg.Platform
	if err := downloadAndVerify(ctx, cfg, url, wantHex, cfg.BinaryPath+".new"); err != nil {
		return "", err
	}
	return m.version, nil
}

func fetchManifest(ctx context.Context, cfg Config) (*manifest, error) {
	tag, err := latestTag(ctx, cfg)
	if err != nil {
		return nil, err
	}
	newer, err := versionLess(cfg.Version, tag)
	if err != nil {
		return nil, err
	}
	if !newer {
		return nil, errNoUpdate
	}

	if !isHTTPSOrLoopback(cfg.SigURL) {
		return nil, errors.New("signature URL must be https")
	}
	client := httpClient()

	checksumsURL := cfg.ChecksumsURL
	if checksumsURL == "" {
		checksumsURL = fmt.Sprintf("https://github.com/%s/releases/latest/download/checksums.txt", cfg.Repo)
	}
	checksumsRaw, err := getBytes(ctx, cfg, client, checksumsURL, maxManifestSize)
	if err != nil {
		return nil, err
	}
	sig, err := getBytes(ctx, cfg, client, cfg.SigURL, maxSigSize)
	if err != nil {
		return nil, err
	}
	signedBy, err := verify(checksumsRaw, sig)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	m, err := parseManifest(checksumsRaw)
	if err != nil {
		return nil, err
	}
	if strings.TrimPrefix(m.version, "v") != strings.TrimPrefix(tag, "v") {
		return nil, fmt.Errorf("%w: signed version does not match release tag", ErrVerificationFailed)
	}
	newer2, err := versionLess(cfg.Version, m.version)
	if err != nil || !newer2 {
		return nil, fmt.Errorf("%w: signed version is not newer", ErrVerificationFailed)
	}
	if _, ok := m.digests[cfg.Platform]; !ok {
		return nil, fmt.Errorf("no signed digest for %s", cfg.Platform)
	}
	m.signedBy = signedBy
	return m, nil
}

func latestTag(ctx context.Context, cfg Config) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimSuffix(cfg.APIBase, "/"), cfg.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: status %d", resp.StatusCode)
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifestSize)).Decode(&payload); err != nil {
		return "", err
	}
	if _, _, _, err := parseVersion(payload.TagName); err != nil {
		return "", errors.New("invalid release tag")
	}
	return payload.TagName, nil
}

func getBytes(ctx context.Context, cfg Config, client *http.Client, url string, cap int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", hostOf(url), resp.StatusCode)
	}
	if resp.ContentLength > cap {
		return nil, fmt.Errorf("fetch %s: too large", hostOf(url))
	}
	return io.ReadAll(io.LimitReader(resp.Body, cap+1))
}

func downloadAndVerify(ctx context.Context, cfg Config, url, wantHex, dest string) error {
	want, err := hex.DecodeString(wantHex)
	if err != nil || len(want) != sha256.Size {
		return errors.New("invalid expected digest")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: status %d", hostOf(url), resp.StatusCode)
	}
	if resp.ContentLength > maxBinarySize {
		return errors.New("asset too large")
	}

	// Unique temp in the binary's dir (O_EXCL) so concurrent applies can't
	// interleave writes into the same file.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".shells-new-*.tmp")
	if err != nil {
		return err
	}
	f := tmp
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(resp.Body, maxBinarySize+1))
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	if n > maxBinarySize {
		os.Remove(f.Name())
		return errors.New("asset exceeds size cap")
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), want) != 1 {
		os.Remove(f.Name())
		return fmt.Errorf("%w: sha256 mismatch on downloaded binary", ErrVerificationFailed)
	}
	if err := os.Rename(f.Name(), dest); err != nil {
		os.Remove(f.Name())
		return err
	}
	// Sidecar digest lets the parent re-verify the staged file (and reject
	// symlinks / tampering) before it ever executes or swaps it in.
	_ = os.WriteFile(dest+".sha256", []byte(hex.EncodeToString(want)), 0o600)
	return os.Chmod(dest, 0o755)
}

func parseManifest(raw []byte) (*manifest, error) {
	m := &manifest{digests: make(map[string]string)}
	lines := strings.Split(string(raw), "\n")
	if len(lines) == 0 {
		return nil, errors.New("empty checksums file")
	}
	header := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(header, "# shells ") {
		return nil, errors.New("missing version header")
	}
	ver := strings.TrimSpace(strings.TrimPrefix(header, "# shells "))
	if _, _, _, err := parseVersion(ver); err != nil {
		return nil, errors.New("invalid version header")
	}
	m.version = ver

	seen := make(map[string]bool)
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, errors.New("malformed checksum line")
		}
		sum, name := f[0], f[1]
		if len(sum) != 64 {
			return nil, errors.New("bad digest length")
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, errors.New("bad digest hex")
		}
		if seen[name] {
			return nil, errors.New("duplicate asset line")
		}
		seen[name] = true
		m.digests[name] = sum
	}
	if len(m.digests) == 0 {
		return nil, errors.New("no digests parsed")
	}
	return m, nil
}

// httpClient returns a client with an SSRF-guarded redirect policy.
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			u := req.URL
			if u.Scheme != "https" {
				return errors.New("non-https redirect")
			}
			switch u.Hostname() {
			case "api.github.com", "github.com",
				"objects.githubusercontent.com", "release-assets.githubusercontent.com",
				"socket.cat":
				return nil
			}
			return fmt.Errorf("redirect to disallowed host %q", u.Hostname())
		},
	}
}

// isHTTPSOrLoopback allows https in production and http on loopback only
// (for local e2e mocks).
func isHTTPSOrLoopback(rawurl string) bool {
	if strings.HasPrefix(rawurl, "https://") {
		return true
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	if u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func hostOf(rawurl string) string {
	if i := strings.Index(rawurl, "://"); i >= 0 {
		rest := rawurl[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	return rawurl
}

// Platform derives the asset basename for the current build target.
func Platform() string {
	return "shells-" + runtime.GOOS + "-" + runtime.GOARCH
}
