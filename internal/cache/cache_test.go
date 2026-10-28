package cache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewCache(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned nil")
	}
	if c.ResolvedPURLs == nil {
		t.Error("ResolvedPURLs map not initialized")
	}
	if c.Copyrights == nil {
		t.Error("Copyrights map not initialized")
	}
	if c.Licenses == nil {
		t.Error("Licenses map not initialized")
	}
}

func TestCacheGetSet(t *testing.T) {
	c := New()

	// Test ResolvedPURL
	purl := "pkg:golang/example@1.0.0"
	resolved := "pkg:github/github.com/example/repo"

	// Should not exist initially
	if _, ok := c.GetResolvedPURL(purl); ok {
		t.Error("Expected GetResolvedPURL to return false for non-existent key")
	}

	// Set and get
	c.SetResolvedPURL(purl, resolved)
	if val, ok := c.GetResolvedPURL(purl); !ok || val != resolved {
		t.Errorf("GetResolvedPURL() = %v, %v; want %v, true", val, ok, resolved)
	}

	// Test Copyright
	copyright := "Copyright 2024 Example Corp"

	// Should not exist initially
	if _, ok := c.GetCopyright(resolved); ok {
		t.Error("Expected GetCopyright to return false for non-existent key")
	}

	// Set and get
	c.SetCopyright(resolved, copyright)
	if val, ok := c.GetCopyright(resolved); !ok || val != copyright {
		t.Errorf("GetCopyright() = %v, %v; want %v, true", val, ok, copyright)
	}

	// Test License
	license := "Apache-2.0"

	// Should not exist initially
	if _, ok := c.GetLicense(resolved); ok {
		t.Error("Expected GetLicense to return false for non-existent key")
	}

	// Set and get
	c.SetLicense(resolved, license)
	if val, ok := c.GetLicense(resolved); !ok || val != license {
		t.Errorf("GetLicense() = %v, %v; want %v, true", val, ok, license)
	}
}

func TestCacheSaveLoad(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "test_cache.json")

	// Create and populate cache
	c1 := New()
	c1.SetResolvedPURL("pkg:golang/test@1.0.0", "pkg:github/github.com/test/repo")
	c1.SetCopyright("pkg:github/github.com/test/repo", "Copyright 2024 Test")
	c1.SetLicense("pkg:github/github.com/test/repo", "MIT")

	// Save cache
	if err := c1.Save(cachePath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Fatal("Cache file was not created")
	}

	// Load into new cache
	c2 := New()
	if err := c2.Load(cachePath); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify data was loaded correctly
	if val, ok := c2.GetResolvedPURL("pkg:golang/test@1.0.0"); !ok || val != "pkg:github/github.com/test/repo" {
		t.Errorf("Loaded ResolvedPURL incorrect: got %v, %v", val, ok)
	}

	if val, ok := c2.GetCopyright("pkg:github/github.com/test/repo"); !ok || val != "Copyright 2024 Test" {
		t.Errorf("Loaded Copyright incorrect: got %v, %v", val, ok)
	}

	if val, ok := c2.GetLicense("pkg:github/github.com/test/repo"); !ok || val != "MIT" {
		t.Errorf("Loaded License incorrect: got %v, %v", val, ok)
	}
}

func TestCacheLoadNonExistent(t *testing.T) {
	c := New()

	// Loading non-existent file should not error
	err := c.Load("/nonexistent/path/cache.json")
	if err != nil {
		t.Errorf("Load() of non-existent file should not error, got: %v", err)
	}

	// Cache should still be usable with empty maps
	c.SetResolvedPURL("test", "value")
	if val, ok := c.GetResolvedPURL("test"); !ok || val != "value" {
		t.Error("Cache should be usable after failed load")
	}
}

func TestCacheConcurrency(t *testing.T) {
	c := New()
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(n int) {
			purl := "pkg:test/" + string(rune('a'+n))
			c.SetResolvedPURL(purl, "resolved")
			c.SetCopyright(purl, "copyright")
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(n int) {
			purl := "pkg:test/" + string(rune('a'+n))
			c.GetResolvedPURL(purl)
			c.GetCopyright(purl)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
