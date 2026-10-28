package copyright

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/go-github/v66/github"
	"github.com/package-url/packageurl-go"
)

// Common errors for circuit breaking in CI pipelines.
var (
	ErrAuthenticationFailed = errors.New("github authentication failed (HTTP 401)")
	ErrRateLimitExceeded    = errors.New("github api rate limit exceeded (HTTP 403/429)")
)

// Finder handles copyright lookups.
type Finder struct {
	client *github.Client
}

// NewFinder creates a new copyright finder with the given token.
func NewFinder(token string) *Finder {
	client := github.NewClient(nil).WithAuthToken(token)
	return &Finder{client: client}
}

// FindCopyright attempts to find copyright information for a given PURL (single notice convenience).
func (f *Finder) FindCopyright(ctx context.Context, purl string) (string, error) {
	notices, err := f.FindCopyrights(ctx, purl)
	if err != nil {
		return "", err
	}
	if len(notices) == 0 {
		return "", nil
	}
	return notices[0], nil
}

// FindCopyrights attempts to find all distinct copyright statements for a given PURL.
// It parses the PURL, checks release commit/tag if available, and extracts co-author notices.
func (f *Finder) FindCopyrights(ctx context.Context, purl string) ([]string, error) {
	owner, repo, ref, err := parseGitHubPURL(purl)
	if err != nil || owner == "" || repo == "" {
		return nil, nil // Not resolvable to GitHub
	}

	opts := &github.RepositoryContentGetOptions{}
	if ref != "" {
		opts.Ref = ref
	}

	// 1. Try standard License API first (if no specific ref requested)
	if ref == "" {
		license, resp, err := f.client.Repositories.License(ctx, owner, repo)
		if circuitErr := f.checkCircuitBreaker(resp, err); circuitErr != nil {
			return nil, circuitErr
		}
		if err == nil && license != nil && license.Content != nil {
			content, err := base64.StdEncoding.DecodeString(*license.Content)
			if err == nil {
				if cpy := ExtractCopyrights(string(content)); len(cpy) > 0 {
					return cpy, nil
				}
			}
		}
	}

	// 2. Check canonical license and notice files (respecting ref if specified)
	filesToCheck := []string{"LICENSE", "LICENSE.txt", "NOTICE", "NOTICE.txt", "COPYING", "LICENSE.md", "README.md"}
	for _, file := range filesToCheck {
		content, resp, err := f.getFileContent(ctx, owner, repo, file, opts)
		if circuitErr := f.checkCircuitBreaker(resp, err); circuitErr != nil {
			return nil, circuitErr
		}
		if err == nil && content != "" {
			if cpy := ExtractCopyrights(content); len(cpy) > 0 {
				return cpy, nil
			}
		}
	}

	// Return empty slice (nil) when not found, NOT a sentinel string
	return nil, nil
}

func parseGitHubPURL(rawPURL string) (owner, repo, ref string, err error) {
	trimmed := strings.TrimSpace(rawPURL)
	if trimmed == "" {
		return "", "", "", nil
	}

	// Try standard packageurl-go parser
	if p, err := packageurl.FromString(trimmed); err == nil {
		ref = p.Version
		// Handle Go pseudo-versions: extract trailing 12-char commit SHA if present
		if strings.HasPrefix(p.Version, "v0.0.0-") && len(p.Version) >= 12 {
			ref = p.Version[len(p.Version)-12:]
		}

		if p.Type == "golang" {
			// pkg:golang/github.com/owner/repo
			ns := strings.TrimPrefix(p.Namespace, "github.com/")
			ns = strings.TrimPrefix(ns, "github.com")
			parts := strings.Split(strings.Trim(ns, "/"), "/")
			if len(parts) >= 1 && parts[0] != "" {
				owner = parts[0]
				repo = p.Name
				return owner, repo, ref, nil
			}
		} else if p.Type == "github" {
			// pkg:github/owner/repo
			if p.Namespace != "" && p.Name != "" {
				return p.Namespace, p.Name, ref, nil
			}
			parts := strings.Split(p.Name, "/")
			if len(parts) >= 2 {
				return parts[0], parts[1], ref, nil
			}
		}
	}

	// Fallback to substring matching
	if !strings.Contains(trimmed, "github.com/") {
		return "", "", "", nil
	}

	parts := strings.Split(trimmed, "github.com/")
	if len(parts) < 2 {
		return "", "", "", nil
	}

	repoPath := parts[1]
	if idx := strings.Index(repoPath, "@"); idx != -1 {
		ref = repoPath[idx+1:]
		repoPath = repoPath[:idx]
	}

	pathParts := strings.Split(strings.Trim(repoPath, "/"), "/")
	if len(pathParts) >= 2 {
		return pathParts[0], pathParts[1], ref, nil
	}

	return "", "", "", nil
}

func (f *Finder) checkCircuitBreaker(resp *github.Response, err error) error {
	if resp != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return ErrAuthenticationFailed
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			if resp.Rate.Remaining == 0 {
				return ErrRateLimitExceeded
			}
		}
		if resp.Rate.Remaining < 20 && resp.Rate.Remaining > 0 {
			slog.Warn("GitHub API rate limit critical", "remaining", resp.Rate.Remaining, "reset", resp.Rate.Reset)
		}
	}
	return nil
}

func (f *Finder) getFileContent(ctx context.Context, owner, repo, path string, opts *github.RepositoryContentGetOptions) (string, *github.Response, error) {
	fileContent, _, resp, err := f.client.Repositories.GetContents(ctx, owner, repo, path, opts)
	if err != nil {
		return "", resp, err
	}
	if fileContent == nil || fileContent.Content == nil {
		return "", resp, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(*fileContent.Content)
	if err != nil {
		return "", resp, err
	}
	return string(decoded), resp, nil
}

var copyrightRegex = regexp.MustCompile(`(?i)(copyright\s+(\(c\)\s+|©\s+)?|©\s+|\(c\)\s+)`)

// ExtractCopyrights extracts all unique, clean copyright notices from text content.
func ExtractCopyrights(content string) []string {
	lines := strings.Split(content, "\n")
	var notices []string
	seen := make(map[string]bool)

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// Strip comment markers
		line = strings.TrimPrefix(line, "//")
		line = strings.TrimPrefix(line, "/*")
		line = strings.TrimPrefix(line, "*")
		line = strings.TrimPrefix(line, "#")
		line = strings.TrimSpace(line)

		if len(line) == 0 || len(line) > 500 {
			continue
		}

		if copyrightRegex.MatchString(line) {
			lower := strings.ToLower(line)
			// Filter out common documentation boilerplate and false positives
			if strings.Contains(lower, "see the copyright") ||
				strings.Contains(lower, "see copyright") ||
				strings.Contains(lower, "copyright notice") ||
				strings.Contains(lower, "copyright and related rights") ||
				strings.Contains(lower, "without copyright") ||
				strings.Contains(lower, "without any copyright") {
				continue
			}

			// Capture wrapped lines if current line ends without period and next line looks like organization name
			if i+1 < len(lines) && (strings.HasSuffix(lower, "by") || strings.HasSuffix(lower, "copyright (c)") || strings.HasSuffix(lower, "copyright")) {
				nextLine := strings.TrimSpace(lines[i+1])
				nextLine = strings.TrimPrefix(nextLine, "//")
				nextLine = strings.TrimPrefix(nextLine, "*")
				nextLine = strings.TrimSpace(nextLine)
				if len(nextLine) > 0 && len(nextLine) < 100 {
					line = line + " " + nextLine
					i++
				}
			}

			normalized := strings.Join(strings.Fields(line), " ")
			if !seen[normalized] {
				seen[normalized] = true
				notices = append(notices, normalized)
			}
		}
	}

	return notices
}
