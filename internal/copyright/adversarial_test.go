package copyright

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v66/github"
)

// TestAdversarial_ReDoSAndPathologicalLineLengths verifies that huge or pathological
// lines do not cause catastrophic backtracking or CPU exhaustion in ExtractCopyrights.
func TestAdversarial_ReDoSAndPathologicalLineLengths(t *testing.T) {
	hugeLine := "Copyright (c) " + strings.Repeat("A", 100000)
	start := time.Now()
	notices := ExtractCopyrights(hugeLine)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("ReDoS or performance regression detected: line parsing took %v", elapsed)
	}

	// Lines > 500 chars are safely discarded per parser policy
	if len(notices) != 0 {
		t.Errorf("Expected huge line (>500 chars) to be discarded, but got: %v", notices)
	}
}

// TestAdversarial_DeceptiveNoticeFiltering verifies that deceptive documentation
// lines or false-positive disclaimers are correctly rejected.
func TestAdversarial_DeceptiveNoticeFiltering(t *testing.T) {
	deceptiveInputs := []string{
		"Please see the copyright notice in the root directory",
		"See copyright information for license details",
		"This software is provided without copyright warranty",
		"Refer to copyright notice in the accompanying documentation",
		"All rights reserved without any copyright restrictions",
	}

	for _, input := range deceptiveInputs {
		notices := ExtractCopyrights(input)
		if len(notices) != 0 {
			t.Errorf("Deceptive input was accepted as valid copyright: %q -> %v", input, notices)
		}
	}
}

// TestAdversarial_MultiAuthorNoticeRetention verifies that in large projects with many
// contributors and co-authors, ALL distinct copyright notices are captured.
func TestAdversarial_MultiAuthorNoticeRetention(t *testing.T) {
	var input strings.Builder
	for i := 2010; i <= 2026; i++ {
		input.WriteString(fmt.Sprintf("Copyright (c) %d Contributor %d <dev%d@example.org>\n", i, i, i))
	}

	notices := ExtractCopyrights(input.String())
	expectedCount := 2026 - 2010 + 1
	if len(notices) != expectedCount {
		t.Fatalf("Expected %d notices, got %d", expectedCount, len(notices))
	}

	for i, notice := range notices {
		expectedYear := 2010 + i
		if !strings.Contains(notice, fmt.Sprintf("%d Contributor %d", expectedYear, expectedYear)) {
			t.Errorf("Notice %d mismatch: got %q", i, notice)
		}
	}
}

// TestAdversarial_CircuitBreaker_401Unauthorized verifies that when the GitHub API
// returns HTTP 401 Bad Credentials, the finder immediately triggers ErrAuthenticationFailed.
func TestAdversarial_CircuitBreaker_401Unauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, `{"message": "Bad credentials", "documentation_url": "https://docs.github.com/rest"}`)
	}))
	defer ts.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = github.NewClient(nil).BaseURL.Parse(ts.URL + "/")

	finder := &Finder{client: client}
	_, err := finder.FindCopyrights(context.Background(), "pkg:github/owner/repo@v1.0.0")

	if err != ErrAuthenticationFailed {
		t.Fatalf("Expected ErrAuthenticationFailed, got: %v", err)
	}
}

// TestAdversarial_CircuitBreaker_RateLimitExceeded verifies that HTTP 403 with
// X-RateLimit-Remaining: 0 immediately returns ErrRateLimitExceeded.
func TestAdversarial_CircuitBreaker_RateLimitExceeded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, `{"message": "API rate limit exceeded", "documentation_url": "https://docs.github.com/rest"}`)
	}))
	defer ts.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = github.NewClient(nil).BaseURL.Parse(ts.URL + "/")

	finder := &Finder{client: client}
	_, err := finder.FindCopyrights(context.Background(), "pkg:github/owner/repo@v1.0.0")

	if err != ErrRateLimitExceeded {
		t.Fatalf("Expected ErrRateLimitExceeded, got: %v", err)
	}
}

// TestAdversarial_BMH01_EncodedPURLTraversalAndTokenPinning verifies:
//  1. Percent-encoded path traversal (%2e%2e%2f), dot segments, query/fragment injection in PURLs
//     are rejected BEFORE any GitHub API request is issued.
//  2. authPinningTransport ONLY attaches Authorization: Bearer to https://api.github.com.
func TestAdversarial_BMH01_EncodedPURLTraversalAndTokenPinning(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = github.NewClient(nil).BaseURL.Parse(ts.URL + "/")
	finder := &Finder{client: client}

	maliciousPURLs := []string{
		"pkg:github/..%2f..%2fusers/victim@v1.0.0",
		"pkg:github/owner/..%2f..%2forg%2fsecret-repo@v1.0.0",
		"pkg:github/./repo@v1.0.0",
		"pkg:github/owner/..@v1.0.0",
		"pkg:github/owner/repo%3fadmin=1@v1.0.0",
		"pkg:github/owner/repo%23frag@v1.0.0",
		"pkg:golang/github.com/owner/..%2fsecret@v1.0.0",
	}

	for _, purl := range maliciousPURLs {
		_, err := finder.FindCopyrights(context.Background(), purl)
		if err == nil {
			t.Fatalf("BMH-01 regression: malicious PURL %q was accepted!", purl)
		}
	}
	if requestCount != 0 {
		t.Fatalf("BMH-01 regression: %d HTTP requests were sent for invalid/traversal PURLs!", requestCount)
	}

	// Verify authPinningTransport never leaks token to non-api.github.com hosts or plain HTTP
	var capturedAuth string
	roundTripFunc := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		capturedAuth = req.Header.Get("Authorization")
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	tr := &authPinningTransport{base: roundTripFunc, token: "ghp_super_secret_token"}

	evilReq, _ := http.NewRequest("GET", "https://evil.example.com/repos/a/b/license", nil)
	_, _ = tr.RoundTrip(evilReq)
	if capturedAuth != "" {
		t.Fatalf("BMH-01 regression: Bearer token leaked to evil host: %q", capturedAuth)
	}

	httpDowngradeReq, _ := http.NewRequest("GET", "http://api.github.com/repos/a/b/license", nil)
	_, _ = tr.RoundTrip(httpDowngradeReq)
	if capturedAuth != "" {
		t.Fatalf("BMH-01 regression: Bearer token leaked over cleartext HTTP: %q", capturedAuth)
	}

	legitReq, _ := http.NewRequest("GET", "https://api.github.com/repos/a/b/license", nil)
	_, _ = tr.RoundTrip(legitReq)
	if capturedAuth != "Bearer ghp_super_secret_token" {
		t.Fatalf("Expected Bearer token on https://api.github.com, got: %q", capturedAuth)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestAdversarial_BMH06_HTTP429RateLimit verifies HTTP 429 Too Many Requests immediately trips ErrRateLimitExceeded.
func TestAdversarial_BMH06_HTTP429RateLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintln(w, `{"message": "secondary rate limit"}`)
	}))
	defer ts.Close()

	client := github.NewClient(nil)
	client.BaseURL, _ = github.NewClient(nil).BaseURL.Parse(ts.URL + "/")
	finder := &Finder{client: client}

	_, err := finder.FindCopyrights(context.Background(), "pkg:github/owner/repo@v1.0.0")
	if err != ErrRateLimitExceeded {
		t.Fatalf("Expected ErrRateLimitExceeded on HTTP 429, got: %v", err)
	}
}
