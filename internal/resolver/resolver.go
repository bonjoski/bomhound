package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bonjoski/bomhound/internal/safehttp"
)

var npmRegistryBase = "https://registry.npmjs.org/"

var defaultHTTPClient = safehttp.NewSafeHTTPClient(10 * time.Second)

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
	// Example PURL: pkg:npm/@auth0/auth0-spa-js@2.0.7
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
	// Extract package name
	// pkg:npm/scope/name@version or pkg:npm/name@version
	parts := strings.Split(purl, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid npm purl: %s", purl)
	}

	// Remove "pkg:npm" prefix
	path := purl[8:]

	// Handle version if present
	if idx := strings.LastIndex(path, "@"); idx != -1 {
		path = path[:idx]
	}

	// Construct registry URL
	url := fmt.Sprintf("%s%s", npmRegistryBase, path)

	resp, err := defaultHTTPClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch npm registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	var info npmPackageInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to decode npm response: %w", err)
	}

	repoURL := info.Repository.URL
	return cleanRepoURL(repoURL), nil
}

func cleanRepoURL(url string) string {
	// Normalize URL to be github.com/owner/repo
	// Examples:
	// git+https://github.com/owner/repo.git
	// git://github.com/owner/repo.git
	// https://github.com/owner/repo

	url = strings.TrimSpace(url)
	url = strings.TrimPrefix(url, "git+")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "ssh://git@")

	url = strings.TrimSuffix(url, ".git")

	// Ensure it starts with github.com if it's a github repo
	if strings.HasPrefix(url, "github.com/") {
		return url
	}

	return url
}
