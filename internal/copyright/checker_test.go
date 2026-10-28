package copyright

import (
	"context"
	"testing"
)

func TestExtractCopyrights_MultiAuthor(t *testing.T) {
	content := `
/*
 * Copyright (c) 2014-2023 Docker, Inc.
 * Copyright (c) 2017-2023 Containerd Authors
 * Copyright (c) 2020 Google LLC
 */

# See copyright notice in LICENSE
`

	notices := ExtractCopyrights(content)
	if len(notices) != 3 {
		t.Fatalf("Expected 3 notices, got %d: %v", len(notices), notices)
	}

	expected := []string{
		"Copyright (c) 2014-2023 Docker, Inc.",
		"Copyright (c) 2017-2023 Containerd Authors",
		"Copyright (c) 2020 Google LLC",
	}

	for i, exp := range expected {
		if notices[i] != exp {
			t.Errorf("Notice %d mismatch: got %q, want %q", i, notices[i], exp)
		}
	}
}

func TestExtractCopyrights_NoTruncation(t *testing.T) {
	longNotice := "Copyright (c) 2026 Very Long Corporate Entity Name With Extensive Legal Subdivision And Joint Intellectual Property Development Consortium Inc."
	notices := ExtractCopyrights(longNotice)
	if len(notices) != 1 {
		t.Fatalf("Expected 1 notice, got %d", len(notices))
	}
	if notices[0] != longNotice {
		t.Errorf("Notice was modified or truncated: got %q", notices[0])
	}
}

func TestParseGitHubPURL(t *testing.T) {
	tests := []struct {
		purl      string
		wantOwner string
		wantRepo  string
		wantRef   string
	}{
		{
			purl:      "pkg:golang/github.com/kubernetes/client-go@v0.28.0",
			wantOwner: "kubernetes",
			wantRepo:  "client-go",
			wantRef:   "v0.28.0",
		},
		{
			purl:      "pkg:golang/github.com/foo/bar@v0.0.0-20210226172049-e18ecbb05110",
			wantOwner: "foo",
			wantRepo:  "bar",
			wantRef:   "e18ecbb05110", // Extracted 12-char commit SHA from pseudo-version
		},
		{
			purl:      "pkg:github/owner/repo@v1.2.3",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantRef:   "v1.2.3",
		},
	}

	for _, tt := range tests {
		owner, repo, ref, err := parseGitHubPURL(tt.purl)
		if err != nil {
			t.Errorf("parseGitHubPURL(%q) unexpected error: %v", tt.purl, err)
		}
		if owner != tt.wantOwner || repo != tt.wantRepo || ref != tt.wantRef {
			t.Errorf("parseGitHubPURL(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tt.purl, owner, repo, ref, tt.wantOwner, tt.wantRepo, tt.wantRef)
		}
	}
}

func TestFindCopyright_IntegrationMock(t *testing.T) {
	finder := NewFinder("mock-token")
	ctx := context.Background()

	// Non-github PURL should return empty without error
	cpy, err := finder.FindCopyright(ctx, "pkg:npm/left-pad@1.3.0")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if cpy != "" {
		t.Errorf("Expected empty string, got %q", cpy)
	}
}
