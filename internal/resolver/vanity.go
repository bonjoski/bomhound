package resolver

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/bonjoski/bomhound/internal/copyright"
	"golang.org/x/mod/module"
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

// ResolveGoVanityURL attempts to resolve a Go vanity URL to its GitHub repository purely offline.
func ResolveGoVanityURL(importPath string) (string, bool) {
	cleanPath := importPath
	if idx := strings.LastIndex(importPath, "/v"); idx != -1 {
		suffix := importPath[idx+2:]
		if len(suffix) > 0 && suffix[0] >= '0' && suffix[0] <= '9' {
			cleanPath = importPath[:idx]
		}
	}

	if repo, ok := specialMappings[cleanPath]; ok {
		return repo, true
	}

	for vanity, gh := range vanityMappings {
		if strings.HasPrefix(importPath, vanity) {
			pkgName := strings.TrimPrefix(importPath, vanity)
			if idx := strings.Index(pkgName, "/"); idx != -1 {
				pkgName = pkgName[:idx]
			}
			if !copyright.IsValidGitHubSegment(pkgName) {
				return "", false
			}
			return gh + pkgName, true
		}
	}

	return "", false
}

// goImportMetaRegex matches go-import meta tags.
var goImportMetaRegex = regexp.MustCompile(`(?i)<meta\s+name=["']go-import["']\s+content=["']([^"']+)["']`)

// FetchGoImportMeta fetches and validates the go-import meta tag from a Go vanity module path.
func FetchGoImportMeta(importPath string) (string, error) {
	trimmed := strings.TrimSpace(importPath)
	if idx := strings.Index(trimmed, "@"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	if err := module.CheckPath(trimmed); err != nil {
		return "", fmt.Errorf("invalid Go module path %q: %w", trimmed, err)
	}

	reqURL, err := url.Parse("https://" + trimmed + "?go-get=1")
	if err != nil || reqURL.User != nil || reqURL.RawQuery != "go-get=1" || reqURL.Fragment != "" || reqURL.Hostname() == "" {
		return "", fmt.Errorf("malformed vanity lookup URL for %q", trimmed)
	}

	resp, err := defaultHTTPClient.Get(reqURL.String())
	if err != nil {
		return "", fmt.Errorf("fetching go-import meta: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	allMatches := goImportMetaRegex.FindAllStringSubmatch(string(body), -1)
	if len(allMatches) == 0 {
		return "", errors.New("no go-import meta tag found")
	}

	for _, match := range allMatches {
		if len(match) < 2 {
			continue
		}
		parts := strings.Fields(match[1])
		if len(parts) != 3 {
			continue
		}
		importPrefix, repoRaw := parts[0], parts[2]
		// Verify meta prefix matches queried module path on a '/' boundary.
		if trimmed != importPrefix && !strings.HasPrefix(trimmed, importPrefix+"/") {
			continue
		}

		ghRepo, ok := extractExactGitHubRepo(repoRaw)
		if ok {
			return ghRepo, nil
		}
	}

	return "", errors.New("no matching GitHub go-import repository found")
}

func extractExactGitHubRepo(rawURL string) (string, bool) {
	cleaned := strings.TrimSpace(rawURL)
	cleaned = strings.TrimPrefix(cleaned, "git+")
	if strings.HasPrefix(cleaned, "ssh://git@github.com/") {
		cleaned = "https://github.com/" + strings.TrimPrefix(cleaned, "ssh://git@github.com/")
	}

	u, err := url.Parse(cleaned)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "git" {
		return "", false
	}
	if !strings.EqualFold(u.Hostname(), "github.com") {
		return "", false
	}

	trimmedPath := strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
	segs := strings.Split(trimmedPath, "/")
	if len(segs) < 2 {
		return "", false
	}
	owner, repo := segs[0], segs[1]
	if !copyright.IsValidGitHubSegment(owner) || !copyright.IsValidGitHubSegment(repo) {
		return "", false
	}
	return "github.com/" + owner + "/" + repo, true
}
