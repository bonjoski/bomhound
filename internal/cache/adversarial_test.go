package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestAdversarial_LostUpdateRaceCondition simulates two independent CI workers
// loading the same cache, discovering distinct dependencies, and saving concurrently.
// It verifies that both sets of discoveries are merged without either job's data being lost.
func TestAdversarial_LostUpdateRaceCondition(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache-race-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sharedCachePath := filepath.Join(tempDir, ".sbom-cache.json")

	// Initial shared cache state
	baseCache := New()
	baseCache.SetCopyright("pkg:golang/github.com/base/pkg", "Copyright (c) Base")
	if err := baseCache.Save(sharedCachePath); err != nil {
		t.Fatalf("Failed to write initial cache: %v", err)
	}

	// Job A loads cache
	jobA := New()
	if err := jobA.Load(sharedCachePath); err != nil {
		t.Fatalf("Job A failed to load cache: %v", err)
	}
	jobA.SetCopyright("pkg:golang/github.com/jobA/pkg", "Copyright (c) Job A")

	// Job B loads cache concurrently
	jobB := New()
	if err := jobB.Load(sharedCachePath); err != nil {
		t.Fatalf("Job B failed to load cache: %v", err)
	}
	jobB.SetCopyright("pkg:golang/github.com/jobB/pkg", "Copyright (c) Job B")

	// Job A saves first
	if err := jobA.Save(sharedCachePath); err != nil {
		t.Fatalf("Job A save failed: %v", err)
	}

	// Job B saves second (would clobber Job A in a naive write)
	if err := jobB.Save(sharedCachePath); err != nil {
		t.Fatalf("Job B save failed: %v", err)
	}

	// Final verification: Load shared cache from disk
	finalCache := New()
	if err := finalCache.Load(sharedCachePath); err != nil {
		t.Fatalf("Failed to reload merged cache: %v", err)
	}

	// Check that Base, Job A, and Job B entries ALL exist
	if cpy, ok := finalCache.GetCopyright("pkg:golang/github.com/base/pkg"); !ok || cpy != "Copyright (c) Base" {
		t.Errorf("Base entry missing or corrupted: got (%q, %v)", cpy, ok)
	}

	if cpy, ok := finalCache.GetCopyright("pkg:golang/github.com/jobA/pkg"); !ok || cpy != "Copyright (c) Job A" {
		t.Fatalf("CRITICAL RACE CONDITION: Job A's cache entries were wiped out by Job B!")
	}

	if cpy, ok := finalCache.GetCopyright("pkg:golang/github.com/jobB/pkg"); !ok || cpy != "Copyright (c) Job B" {
		t.Fatalf("CRITICAL: Job B's cache entries were not saved!")
	}
}

// TestAdversarial_CachePermissions verifies that cache files are written with
// private 0600 permissions rather than world-readable permissions.
func TestAdversarial_CachePermissions(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache-perm-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cachePath := filepath.Join(tempDir, "secure-cache.json")
	c := New()
	c.SetCopyright("pkg:golang/github.com/test/pkg", "Copyright (c) 2026")
	if err := c.Save(cachePath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	fi, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	perm := fi.Mode().Perm()
	// Must not be world-readable (permission mask & 0004 must be 0)
	if perm&0004 != 0 {
		t.Errorf("Security risk: cache file is world-readable! Permissions: %o", perm)
	}
}

// TestAdversarial_NegativeCachingTTL verifies that negative lookup timestamps
// properly expire after the TTL duration.
func TestAdversarial_NegativeCachingTTL(t *testing.T) {
	c := New()
	missingPURL := "pkg:golang/github.com/missing/pkg@v1.0.0"

	c.SetNegative(missingPURL)

	// Within TTL: should be recognized as negative
	if !c.IsNegative(missingPURL, 1*time.Hour) {
		t.Errorf("Expected PURL to be recognized as negative within TTL")
	}

	// After TTL expiration (simulated with 0 millisecond TTL): should expire
	if c.IsNegative(missingPURL, -1*time.Second) {
		t.Errorf("Expected negative cache entry to be expired")
	}
}

// TestAdversarial_ContentAddressedDirStore verifies concurrent writes and reads
// to the directory-backed entry store without data races or corruption.
func TestAdversarial_ContentAddressedDirStore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "dir-store-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	c := New()
	if err := c.SetDirStore(tempDir); err != nil {
		t.Fatalf("SetDirStore failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			purl := fmt.Sprintf("pkg:golang/github.com/org/repo-%d@v1.0.0", idx)
			cpy := fmt.Sprintf("Copyright (c) %d", idx)
			c.SetCopyright(purl, cpy)

			// Read it back
			got, ok := c.GetCopyright(purl)
			if !ok || got != cpy {
				t.Errorf("Worker %d: expected %q, got %q", idx, cpy, got)
			}
		}(i)
	}

	wg.Wait()
}
