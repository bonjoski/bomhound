package resolver

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/bomhound/internal/safehttp"
)

// Common Go vanity URL mappings
var vanityMappings = map[string]string{
	"golang.org/x/":       "github.com/golang/",
	"k8s.io/":             "github.com/kubernetes/",
	"sigs.k8s.io/":        "github.com/kubernetes-sigs/",
	"go.uber.org/":        "github.com/uber-go/",
	"go.etcd.io/":         "github.com/etcd-io/",
	"cloud.google.com/go": "github.com/googleapis/google-cloud-go",
}

// Special case mappings for packages that don't follow the pattern
var specialMappings = map[string]string{
	"google.golang.org/grpc":     "github.com/grpc/grpc-go",
	"google.golang.org/protobuf": "github.com/protocolbuffers/protobuf-go",
	"google.golang.org/genproto": "github.com/googleapis/go-genproto",
	"google.golang.org/api":      "github.com/googleapis/google-api-go-client",
	"gopkg.in/yaml.v2":           "github.com/go-yaml/yaml",
	"gopkg.in/yaml.v3":           "github.com/go-yaml/yaml",
	"gopkg.in/check.v1":          "github.com/go-check/check",
	"gopkg.in/tomb.v1":           "github.com/go-tomb/tomb",
	"gopkg.in/tomb.v2":           "github.com/go-tomb/tomb",
	"gopkg.in/inf.v0":            "github.com/go-inf/inf",
}

// ResolveGoVanityURL attempts to resolve a Go vanity URL to its GitHub repository
func ResolveGoVanityURL(importPath string) (string, bool) {
	// Remove version suffix if present (e.g., /v2, /v3)
	cleanPath := importPath
	if idx := strings.LastIndex(importPath, "/v"); idx != -1 {
		// Check if what follows is a version number
		suffix := importPath[idx+2:]
		if len(suffix) > 0 && suffix[0] >= '0' && suffix[0] <= '9' {
			cleanPath = importPath[:idx]
		}
	}

	// Check special mappings first (exact match)
	if repo, ok := specialMappings[cleanPath]; ok {
		return repo, true
	}

	// Check prefix mappings
	for vanity, github := range vanityMappings {
		if strings.HasPrefix(importPath, vanity) {
			// Extract the package name after the vanity prefix
			pkgName := strings.TrimPrefix(importPath, vanity)
			// Remove any sub-paths, keep only the repo name
			if idx := strings.Index(pkgName, "/"); idx != -1 {
				pkgName = pkgName[:idx]
			}
			return github + pkgName, true
		}
	}

	return "", false
}

// goImportMetaRegex matches go-import meta tags
var goImportMetaRegex = regexp.MustCompile(`<meta\s+name="go-import"\s+content="([^"]+)"`)

// FetchGoImportMeta fetches the go-import meta tag from a vanity URL
func FetchGoImportMeta(importPath string) (string, error) {
	// Construct the URL to fetch
	url := "https://" + importPath + "?go-get=1"

	// Create SSRF-guarded HTTP client with timeout
	client := safehttp.NewSafeHTTPClient(10 * time.Second)

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetching go-import meta: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Limit response body size to prevent DoS
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	// Find the go-import meta tag
	matches := goImportMetaRegex.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return "", fmt.Errorf("no go-import meta tag found")
	}

	// Parse the content: "import-prefix vcs repo-root"
	parts := strings.Fields(matches[1])
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid go-import content")
	}

	repoURL := parts[2]

	// Extract github.com/owner/repo from the URL
	if strings.Contains(repoURL, "github.com") {
		// Clean up the URL
		repoURL = strings.TrimPrefix(repoURL, "https://")
		repoURL = strings.TrimPrefix(repoURL, "http://")
		repoURL = strings.TrimSuffix(repoURL, ".git")

		// Extract github.com/owner/repo
		if idx := strings.Index(repoURL, "github.com/"); idx != -1 {
			return repoURL[idx:], nil
		}
	}

	return "", fmt.Errorf("not a GitHub repository")
}
