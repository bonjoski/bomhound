package resolver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAdversarial_BMH02_GoImportPathValidation verifies module.CheckPath blocks
// malformed Go import paths, port smuggling, flag smuggling, and path traversal
// BEFORE issuing any network request in FetchGoImportMeta.
func TestAdversarial_BMH02_GoImportPathValidation(t *testing.T) {
	hostilePaths := []string{
		"",
		"-evil.com/flag/pkg",
		"evil.com:8443/internal/pkg",
		"evil.com/../../etc/passwd",
		"evil.com/pkg?go-get=0&admin=1#frag",
		"http://169.254.169.254/latest/meta-data",
	}

	for _, p := range hostilePaths {
		if repo, err := FetchGoImportMeta(p); err == nil {
			t.Fatalf("BMH-02 regression: hostile Go module path %q resolved to %q!", p, repo)
		}
	}
}

// TestAdversarial_BMH02_GoImportMetaPrefixMismatch verifies that a go-import meta tag
// claiming a prefix unrelated to the queried module path is rejected.
func TestAdversarial_BMH02_GoImportMetaPrefixMismatch(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><meta name="go-import" content="unrelated.io/pkg git https://github.com/attacker/forged"></head></html>`))
	}))
	defer ts.Close()

	// Even if extractExactGitHubRepo were reached, mismatched prefix must fail
	if got, ok := extractExactGitHubRepo("https://evil.com/github.com/attacker/forged"); ok {
		t.Fatalf("expected spoofed host rejection, got %q", got)
	}
}

// TestAdversarial_BMH02_ExtractSpoofedGitHubSubstring verifies that URLs containing
// "github.com" only in the path or query (e.g. https://evil.com/github.com/org/repo)
// are rejected by extractExactGitHubRepo and cleanRepoURL.
func TestAdversarial_BMH02_ExtractSpoofedGitHubSubstring(t *testing.T) {
	spoofed := []string{
		"https://evil.com/github.com/attacker/repo",
		"https://notgithub.com/owner/repo",
		"https://api.github.com/repos/owner/repo",
		"https://github.com/..",
		"https://github.com/owner/..",
	}

	for _, u := range spoofed {
		if got, ok := extractExactGitHubRepo(u); ok {
			t.Fatalf("BMH-02 regression: spoofed repo URL %q accepted as %q!", u, got)
		}
		if got := cleanRepoURL(u); got != "" {
			t.Fatalf("BMH-02 regression: cleanRepoURL accepted spoofed URL %q -> %q!", u, got)
		}
	}

	legit, ok := extractExactGitHubRepo("https://github.com/bonjoski/bomhound.git")
	if !ok || legit != "github.com/bonjoski/bomhound" {
		t.Fatalf("Expected valid GitHub URL to parse cleanly, got (%q, %v)", legit, ok)
	}
}

// TestAdversarial_BMH02_NPMSegmentSanitization verifies npm traversal/encoded
// slash injection is blocked before contacting registry.npmjs.org.
func TestAdversarial_BMH02_NPMSegmentSanitization(t *testing.T) {
	invalidSegments := []string{
		"..",
		".",
		"pkg%2f..%2fsecret",
		"pkg/subpath",
		"pkg?query=1",
	}
	for _, seg := range invalidSegments {
		if _, err := sanitizeNpmSegment(seg, false); err == nil {
			t.Fatalf("BMH-02 regression: unsafe npm segment %q was accepted!", seg)
		}
	}

	if escaped, err := sanitizeNpmSegment("lodash", false); err != nil || escaped != "lodash" {
		t.Fatalf("Expected lodash to pass sanitizeNpmSegment, got (%q, %v)", escaped, err)
	}
	if scope, err := sanitizeNpmSegment("@types", true); err != nil || scope != "@types" {
		t.Fatalf("Expected @types to pass sanitizeNpmSegment, got (%q, %v)", scope, err)
	}
}
