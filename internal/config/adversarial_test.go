package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestAdversarial_PathologicalGlobs verifies that wildcards and complex glob patterns
// do not cause exponential backtracking, timeouts, or panics in IsExcluded.
func TestAdversarial_PathologicalGlobs(t *testing.T) {
	cfg := DefaultConfig()
	// Malicious pathological glob pattern
	pathologicalGlob := strings.Repeat("*", 500) + "a"
	cfg.Exclude.PURLs = []string{pathologicalGlob}
	cfg.Exclude.Names = []string{pathologicalGlob}

	testPURL := "pkg:golang/github.com/" + strings.Repeat("b", 1000)
	testName := strings.Repeat("b", 1000)

	start := time.Now()
	excluded, _ := cfg.IsExcluded(testPURL, testName)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Fatalf("Glob evaluation took too long (%v): potential catastrophic backtracking", elapsed)
	}

	if excluded {
		t.Errorf("Pathological glob falsely matched mismatched target")
	}
}

// TestAdversarial_BypassAttempts ensures case manipulation or trailing slashes
// cannot be used to bypass exclusion rules.
func TestAdversarial_BypassAttempts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Exclude.PURLs = []string{
		"pkg:golang/internal.company.com/*",
	}
	cfg.Exclude.Names = []string{
		"secret-engine",
	}

	bypassAttempts := []struct {
		purl string
		name string
	}{
		{"pkg:golang/INTERNAL.COMPANY.COM/core", "core"},
		{"pkg:golang/internal.company.com/core/", "core"},
		{"pkg:golang/internal.company.com/CORE@v1.0.0", "core"},
		{"pkg:golang/github.com/foo/bar", "SECRET-ENGINE"},
		{"pkg:golang/github.com/foo/bar", "  secret-engine  "},
	}

	for _, attempt := range bypassAttempts {
		excluded, _ := cfg.IsExcluded(attempt.purl, attempt.name)
		if !excluded {
			t.Errorf("Adversarial bypass succeeded: (%q, %q) evaded exclusion rule", attempt.purl, attempt.name)
		}
	}
}

// TestAdversarial_MalformedYAMLTypes verifies that invalid YAML structures
// return structured errors instead of panicking.
func TestAdversarial_MalformedYAMLTypes(t *testing.T) {
	malformedConfigs := []string{
		"version: [1, 2, 3]",                  // Array instead of string
		"exclude: 'should be an object'",       // String instead of map
		"cache:\n  ttl_days: 'not-a-number'", // String instead of int
		"compliance:\n  min_coverage_percent: 'bad-float'",
		"exclude:\n  purls:\n  - valid\n bad_indentation", // Syntax error
	}

	for i, yamlContent := range malformedConfigs {
		tmp, err := os.CreateTemp("", "bad-config-*.yaml")
		if err != nil {
			t.Fatalf("Failed to create temp config: %v", err)
		}
		tmpPath := tmp.Name()
		tmp.WriteString(yamlContent)
		tmp.Close()
		defer os.Remove(tmpPath)

		_, err = LoadConfig(tmpPath)
		if err == nil {
			t.Errorf("Config test %d: expected error for malformed YAML, got nil", i)
		}
	}
}
