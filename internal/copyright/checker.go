package copyright

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/bomhound/internal/safehttp"
	"github.com/google/go-github/v66/github"
	"github.com/package-url/packageurl-go"
)

// Common errors for circuit breaking in CI pipelines.
var (
	ErrAuthenticationFailed = errors.New("github authentication failed (HTTP 401)")
	ErrRateLimitExceeded    = errors.New("github api rate limit exceeded (HTTP 403/429)")
	ErrInvalidGitHubTarget  = errors.New("invalid github owner or repository segment")
)

var (
	gitHubSegmentRegex = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	gitHubRefRegex     = regexp.MustCompile(`^[A-Za-z0-9_./+-]+$`)
)

// authPinningTransport ensures Bearer tokens are only transmitted to api.github.com over HTTPS.
type authPinningTransport struct {
	base  http.RoundTripper
	token string
}

func (t *authPinningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	if t.token != "" &&
		cloned.URL != nil &&
		strings.EqualFold(cloned.URL.Scheme, "https") &&
		strings.EqualFold(cloned.URL.Hostname(), "api.github.com") {
		cloned.Header.Set("Authorization", "Bearer "+t.token)
	} else {
		cloned.Header.Del("Authorization")
	}
	return t.base.RoundTrip(cloned)
}

// Finder handles copyright lookups.
type Finder struct {
	client *github.Client
}

// NewFinder creates a new copyright finder backed by safehttp with host-pinned token auth.
func NewFinder(token string) *Finder {
	httpClient := safehttp.NewClient(15 * time.Second)
	trimmedToken := strings.TrimSpace(token)
	if trimmedToken != "" {
		baseRT := httpClient.Transport
		if baseRT == nil {
			baseRT = http.DefaultTransport
		}
		httpClient.Transport = &authPinningTransport{
			base:  baseRT,
			token: trimmedToken,
		}
	}
	return &Finder{client: github.NewClient(httpClient)}
}

// IsValidGitHubSegment validates a GitHub owner or repository path segment,
// rejecting '.', '..', path separators, query/fragment characters, and percent-encoding.
func IsValidGitHubSegment(seg string) bool {
	if seg == "" || len(seg) > 100 || seg == "." || seg == ".." {
		return false
	}
	return gitHubSegmentRegex.MatchString(seg)
}

func isValidGitHubRef(ref string) bool {
	if ref == "" {
		return true
	}
	if len(ref) > 256 || strings.Contains(ref, "..") || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return false
	}
	return gitHubRefRegex.MatchString(ref)
}

func hasEncodedTraversal(raw string) bool {
	// Strip query/subpath before inspecting coordinates for percent-encoded separators
	coord := raw
	if qIdx := strings.IndexAny(coord, "?#"); qIdx != -1 {
		coord = coord[:qIdx]
	}
	lower := strings.ToLower(coord)
	for _, seq := range []string{"%2f", "%5c", "%2e", "%3f", "%23", "%00", "..", "/./"} {
		if strings.Contains(lower, seq) {
			return true
		}
	}
	if strings.HasSuffix(lower, "/.") {
		return true
	}
	return false
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
func (f *Finder) FindCopyrights(ctx context.Context, purl string) ([]string, error) {
	owner, repo, ref, err := parseGitHubPURL(purl)
	if err != nil {
		return nil, err
	}
	if owner == "" || repo == "" {
		return nil, nil
	}
	if !IsValidGitHubSegment(owner) || !IsValidGitHubSegment(repo) || !isValidGitHubRef(ref) {
		return nil, ErrInvalidGitHubTarget
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

	return nil, nil
}

func parseGitHubPURL(rawPURL string) (owner, repo, ref string, err error) {
	trimmed := strings.TrimSpace(rawPURL)
	if trimmed == "" {
		return "", "", "", nil
	}
	if hasEncodedTraversal(trimmed) {
		return "", "", "", fmt.Errorf("%w: encoded traversal in %q", ErrInvalidGitHubTarget, trimmed)
	}

	// Try standard packageurl-go parser
	if p, pErr := packageurl.FromString(trimmed); pErr == nil {
		ref = p.Version
		if strings.HasPrefix(p.Version, "v0.0.0-") && len(p.Version) >= 12 {
			ref = p.Version[len(p.Version)-12:]
		}

		switch p.Type {
		case "golang":
			ns := strings.Trim(p.Namespace, "/")
			if ns == "github.com" || strings.HasPrefix(ns, "github.com/") {
				rest := strings.TrimPrefix(ns, "github.com")
				rest = strings.Trim(rest, "/")
				parts := strings.Split(rest, "/")
				if len(parts) == 1 && parts[0] != "" {
					owner = parts[0]
					repo = p.Name
				} else if len(parts) >= 2 {
					owner = parts[0]
					repo = parts[1]
				}
			}
		case "github":
			if p.Namespace != "" && p.Name != "" {
				owner = p.Namespace
				repo = p.Name
			} else {
				parts := strings.Split(p.Name, "/")
				if len(parts) == 2 {
					owner = parts[0]
					repo = parts[1]
				}
			}
		}

		if owner != "" || repo != "" {
			if !IsValidGitHubSegment(owner) || !IsValidGitHubSegment(repo) || !isValidGitHubRef(ref) {
				return "", "", "", fmt.Errorf("%w: owner=%q repo=%q", ErrInvalidGitHubTarget, owner, repo)
			}
			return owner, repo, ref, nil
		}
		return "", "", "", nil
	}

	// Strict URL / github.com/<owner>/<repo> fallback (rejecting evil.com/github.com/...).
	candidate := trimmed
	if strings.HasPrefix(candidate, "github.com/") {
		candidate = "https://" + candidate
	}
	if strings.HasPrefix(candidate, "https://") || strings.HasPrefix(candidate, "http://") {
		u, uErr := url.Parse(candidate)
		if uErr != nil || !strings.EqualFold(u.Hostname(), "github.com") || u.RawQuery != "" || u.Fragment != "" {
			return "", "", "", nil
		}
		repoPath := strings.Trim(u.Path, "/")
		if idx := strings.Index(repoPath, "@"); idx != -1 {
			ref = repoPath[idx+1:]
			repoPath = repoPath[:idx]
		}
		pathParts := strings.Split(repoPath, "/")
		if len(pathParts) >= 2 {
			owner, repo = pathParts[0], strings.TrimSuffix(pathParts[1], ".git")
			if !IsValidGitHubSegment(owner) || !IsValidGitHubSegment(repo) || !isValidGitHubRef(ref) {
				return "", "", "", fmt.Errorf("%w: owner=%q repo=%q", ErrInvalidGitHubTarget, owner, repo)
			}
			return owner, repo, ref, nil
		}
	}

	return "", "", "", nil
}

func (f *Finder) checkCircuitBreaker(resp *github.Response, err error) error {
	if resp != nil {
		if resp.StatusCode == http.StatusUnauthorized {
			return ErrAuthenticationFailed
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return ErrRateLimitExceeded
		}
		if resp.StatusCode == http.StatusForbidden {
			if resp.Rate.Remaining == 0 || resp.Header.Get("Retry-After") != "" {
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
			if strings.Contains(lower, "see the copyright") ||
				strings.Contains(lower, "see copyright") ||
				strings.Contains(lower, "copyright notice") ||
				strings.Contains(lower, "copyright and related rights") ||
				strings.Contains(lower, "without copyright") ||
				strings.Contains(lower, "without any copyright") {
				continue
			}

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
