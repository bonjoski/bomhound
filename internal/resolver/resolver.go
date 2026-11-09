package resolver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bonjoski/bomhound/internal/safehttp"
)

var npmRegistryBase = "https://registry.npmjs.org/"

var defaultHTTPClient = safehttp.NewClient(10 * time.Second)

// SetHTTPClient allows overriding the HTTP client (useful for unit tests with httptest.Server).
func SetHTTPClient(client *http.Client) func() {
	prev := defaultHTTPClient
	defaultHTTPClient = client
	return func() {
		defaultHTTPClient = prev
	}
}

// ResolveRepoURL attempts to find the source repository URL for a given PURL.
func ResolveRepoURL(purl string) (string, error) {
	if strings.HasPrefix(purl, "pkg:npm/") {
		return resolveNpm(purl)
	}
	return "", nil
}

type npmPackageInfo struct {
	Repository struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"repository"`
}

func resolveNpm(purl string) (string, error) {
	if !strings.HasPrefix(purl, "pkg:npm/") {
		return "", fmt.Errorf("invalid npm purl: %s", purl)
	}

	rawCoord := purl[len("pkg:npm/"):]
	// Strip PURL qualifiers or subpaths
	if qIdx := strings.IndexAny(rawCoord, "?#"); qIdx != -1 {
		rawCoord = rawCoord[:qIdx]
	}
	// Strip @version suffix (preserving leading '@' on scoped packages)
	if idx := strings.LastIndex(rawCoord, "@"); idx > 0 {
		rawCoord = rawCoord[:idx]
	}

	// Reject percent-encoded path separators or traversal before unescaping
	lowerCoord := strings.ToLower(rawCoord)
	for _, bad := range []string{"%2f", "%5c", "%2e", "%00", "..", "\\"} {
		if strings.Contains(lowerCoord, bad) {
			return "", fmt.Errorf("invalid npm package path %q", rawCoord)
		}
	}

	rawSegs := strings.Split(rawCoord, "/")
	var escapedPath string
	switch len(rawSegs) {
	case 1:
		name, err := sanitizeNpmSegment(rawSegs[0], false)
		if err != nil {
			return "", err
		}
		escapedPath = url.PathEscape(name)
	case 2:
		scope, err := sanitizeNpmSegment(rawSegs[0], true)
		if err != nil {
			return "", err
		}
		name, err := sanitizeNpmSegment(rawSegs[1], false)
		if err != nil {
			return "", err
		}
		escapedPath = "@" + url.PathEscape(strings.TrimPrefix(scope, "@")) + "/" + url.PathEscape(name)
	default:
		return "", fmt.Errorf("invalid npm package coordinate %q", rawCoord)
	}

	base := strings.TrimRight(npmRegistryBase, "/")
	reqURL := base + "/" + escapedPath

	resp, err := defaultHTTPClient.Get(reqURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch npm registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	var info npmPackageInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to decode npm response: %w", err)
	}

	return cleanRepoURL(info.Repository.URL), nil
}

func sanitizeNpmSegment(seg string, isScope bool) (string, error) {
	decoded, err := url.PathUnescape(seg)
	if err != nil {
		return "", fmt.Errorf("invalid percent-encoding in npm segment %q: %w", seg, err)
	}
	decoded = strings.TrimSpace(decoded)
	if decoded == "" || decoded == "." || decoded == ".." {
		return "", errors.New("empty or dot npm segment")
	}
	if isScope {
		if !strings.HasPrefix(decoded, "@") || len(decoded) < 2 {
			return "", fmt.Errorf("npm scope %q must start with '@'", decoded)
		}
	}
	check := decoded
	if isScope {
		check = decoded[1:]
	}
	if check == "." || check == ".." || strings.ContainsAny(check, "/\\?#%\x00 \t\r\n") {
		return "", fmt.Errorf("unsafe characters in npm segment %q", seg)
	}
	return decoded, nil
}

func cleanRepoURL(rawURL string) string {
	if gh, ok := extractExactGitHubRepo(rawURL); ok {
		return gh
	}
	return ""
}
