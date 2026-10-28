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
