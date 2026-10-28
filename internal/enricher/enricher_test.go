package enricher

import (
	"context"
	"os"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bonjoski/bomhound/internal/cache"
	"github.com/bonjoski/bomhound/internal/config"
	"github.com/bonjoski/bomhound/internal/parser"
)

// MockFinder implements MultiCopyrightFinder
type MockFinder struct {
	results map[string][]string
}

func (m *MockFinder) FindCopyright(ctx context.Context, purl string) (string, error) {
	if res, ok := m.results[purl]; ok && len(res) > 0 {
		return res[0], nil
	}
	if idx := strings.LastIndex(purl, "@"); idx != -1 {
		if res, ok := m.results[purl[:idx]]; ok && len(res) > 0 {
			return res[0], nil
		}
	}
	return "", nil
}

func (m *MockFinder) FindCopyrights(ctx context.Context, purl string) ([]string, error) {
	if res, ok := m.results[purl]; ok {
		return res, nil
	}
	if idx := strings.LastIndex(purl, "@"); idx != -1 {
		if res, ok := m.results[purl[:idx]]; ok {
			return res, nil
		}
	}
	return nil, nil
}

// MockResolver implements RepoResolver
type MockResolver struct {
	results map[string]string
}

func (m *MockResolver) ResolveRepoURL(purl string) (string, error) {
	if res, ok := m.results[purl]; ok {
		return res, nil
	}
	return "", nil
}

func TestEnricher_Caching(t *testing.T) {
	c := cache.New()
	targetPURL := "pkg:github/owner/repo"
	c.SetCopyright(targetPURL, "Copyright (c) Cached")

	finder := &MockFinder{results: make(map[string][]string)}
	resolver := &MockResolver{results: make(map[string]string)}

	e := NewEnricher(finder, resolver, 1, c, config.DefaultConfig())

	comp := &cdx.Component{
		PackageURL: targetPURL,
		Name:       "repo",
	}

	notices, category, err := e.processComponentWithCategory(context.Background(), comp)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(notices) == 0 || notices[0] != "Copyright (c) Cached" {
		t.Errorf("Expected cached notice, got %v", notices)
	}
	if category != "" {
		t.Errorf("Expected empty category on success, got %q", category)
	}
}

func TestEnricher_ExclusionPolicy(t *testing.T) {
	c := cache.New()
	cfg := config.DefaultConfig()
	cfg.Exclude.PURLs = []string{"pkg:golang/internal.corp.com/*"}
	cfg.Exclude.Names = []string{"internal-*"}

	finder := &MockFinder{results: make(map[string][]string)}
	resolver := &MockResolver{results: make(map[string]string)}

	e := NewEnricher(finder, resolver, 1, c, cfg)

	comp1 := &cdx.Component{
		PackageURL: "pkg:golang/internal.corp.com/secret/pkg@v1.0.0",
		Name:       "pkg",
	}
	notices, category, err := e.processComponentWithCategory(context.Background(), comp1)
	if err != nil || category != "excluded" || len(notices) > 0 {
		t.Errorf("Expected excluded category for PURL, got category=%q, err=%v", category, err)
	}

	comp2 := &cdx.Component{
		PackageURL: "pkg:golang/github.com/foo/bar@v1.0.0",
		Name:       "internal-tool",
	}
	notices, category, err = e.processComponentWithCategory(context.Background(), comp2)
	if err != nil || category != "excluded" || len(notices) > 0 {
		t.Errorf("Expected excluded category for name, got category=%q, err=%v", category, err)
	}
}

func TestEnricher_Enrich_Integration(t *testing.T) {
	inputContent := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "name": "test-repo",
      "purl": "pkg:github/owner/test-repo@v1.0.0",
      "type": "library"
    }
  ]
}`
	tmpInput, err := os.CreateTemp("", "enrich-input-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp input: %v", err)
	}
	defer os.Remove(tmpInput.Name())

	if _, err := tmpInput.WriteString(inputContent); err != nil {
		t.Fatalf("Failed to write to temp input: %v", err)
	}
	tmpInput.Close()

	tmpOutput, err := os.CreateTemp("", "enrich-output-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp output: %v", err)
	}
	outputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputPath)

	c := cache.New()
	finder := &MockFinder{
		results: map[string][]string{
			"pkg:github/owner/test-repo": {
				"Copyright (c) 2026 Test Owner",
				"Copyright (c) 2024 Contributor",
			},
		},
	}
	resolver := &MockResolver{results: make(map[string]string)}

	e := NewEnricher(finder, resolver, 2, c, config.DefaultConfig())

	stats, err := e.Enrich(context.Background(), tmpInput.Name(), outputPath)
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}

	if stats.Found != 1 || stats.Missing != 0 {
		t.Errorf("Expected Found=1, Missing=0, got Found=%d, Missing=%d", stats.Found, stats.Missing)
	}

	// Verify enriched output content
	bom, _, err := parser.ParseSBOM(outputPath)
	if err != nil {
		t.Fatalf("Failed to parse enriched SBOM: %v", err)
	}

	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("Expected 1 component in enriched SBOM")
	}

	enrichedComp := (*bom.Components)[0]
	if enrichedComp.Copyright != "Copyright (c) 2026 Test Owner" {
		t.Errorf("Expected primary copyright, got %q", enrichedComp.Copyright)
	}

	if enrichedComp.Evidence == nil || enrichedComp.Evidence.Copyright == nil || len(*enrichedComp.Evidence.Copyright) != 2 {
		t.Fatalf("Expected 2 evidence copyright entries, got %v", enrichedComp.Evidence)
	}
}
