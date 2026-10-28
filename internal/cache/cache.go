package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultNegativeTTL is the duration for which negative (not-found) lookups are cached.
const DefaultNegativeTTL = 7 * 24 * time.Hour

// Cache stores resolved PURLs, copyright notices, license data, and negative lookup timestamps.
type Cache struct {
	ResolvedPURLs   map[string]string `json:"resolved_purls"`
	Copyrights      map[string]string `json:"copyrights"`
	Licenses        map[string]string `json:"licenses,omitempty"`
	NegativeLookups map[string]int64  `json:"negative_lookups,omitempty"` // purl -> unix timestamp
	dirStorePath    string
	mu              sync.RWMutex
}

// New creates a new in-memory Cache.
func New() *Cache {
	return &Cache{
		ResolvedPURLs:   make(map[string]string),
		Copyrights:      make(map[string]string),
		Licenses:        make(map[string]string),
		NegativeLookups: make(map[string]int64),
	}
}

// SetDirStore configures a directory for atomic content-addressed entry caching.
func (c *Cache) SetDirStore(dir string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dirStorePath = dir
	entriesDir := filepath.Join(dir, "entries")
	return os.MkdirAll(entriesDir, 0700)
}

// Load reads the cache from a JSON file.
func (c *Cache) Load(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading cache file: %w", err)
	}

	var diskCache Cache
	if err := json.Unmarshal(data, &diskCache); err != nil {
		return fmt.Errorf("unmarshaling cache: %w", err)
	}

	// Merge disk cache into memory
	if c.ResolvedPURLs == nil {
		c.ResolvedPURLs = make(map[string]string)
	}
	for k, v := range diskCache.ResolvedPURLs {
		c.ResolvedPURLs[k] = v
	}

	if c.Copyrights == nil {
		c.Copyrights = make(map[string]string)
	}
	for k, v := range diskCache.Copyrights {
		c.Copyrights[k] = v
	}

	if c.Licenses == nil {
		c.Licenses = make(map[string]string)
	}
	for k, v := range diskCache.Licenses {
		c.Licenses[k] = v
	}

	if c.NegativeLookups == nil {
		c.NegativeLookups = make(map[string]int64)
	}
	for k, v := range diskCache.NegativeLookups {
		c.NegativeLookups[k] = v
	}

	return nil
}

// Save atomically writes the cache to a JSON file using a read-merge-write strategy
// to prevent lost-update races when multiple concurrent processes share the file.
func (c *Cache) Save(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating cache directory: %w", err)
		}
	}

	// 1. Read existing on-disk state to merge external changes
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		var diskCache Cache
		if err := json.Unmarshal(data, &diskCache); err == nil {
			for k, v := range diskCache.ResolvedPURLs {
				if _, ok := c.ResolvedPURLs[k]; !ok {
					c.ResolvedPURLs[k] = v
				}
			}
			for k, v := range diskCache.Copyrights {
				if _, ok := c.Copyrights[k]; !ok {
					c.Copyrights[k] = v
				}
			}
			for k, v := range diskCache.Licenses {
				if _, ok := c.Licenses[k]; !ok {
					c.Licenses[k] = v
				}
			}
			for k, v := range diskCache.NegativeLookups {
				if _, ok := c.NegativeLookups[k]; !ok {
					c.NegativeLookups[k] = v
				}
			}
		}
	}

	// 2. Marshal merged cache
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cache: %w", err)
	}

	// 3. Write to temporary file with secure 0600 permissions
	tmpFile, err := os.CreateTemp(dir, ".sbom-cache-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary cache file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing temporary cache: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("syncing temporary cache: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temporary cache: %w", err)
	}

	// 4. Atomic commit via os.Rename
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomic cache rename: %w", err)
	}

	return nil
}

// GetResolvedPURL retrieves a resolved PURL from memory or the content-addressed dir store.
func (c *Cache) GetResolvedPURL(purl string) (string, bool) {
	c.mu.RLock()
	val, ok := c.ResolvedPURLs[purl]
	dirStore := c.dirStorePath
	c.mu.RUnlock()

	if ok {
		return val, true
	}

	if dirStore != "" {
		if entry, err := c.readDirEntry(purl); err == nil && entry.ResolvedPURL != "" {
			c.SetResolvedPURL(purl, entry.ResolvedPURL)
			return entry.ResolvedPURL, true
		}
	}

	return "", false
}

// SetResolvedPURL stores a resolved PURL in the cache.
func (c *Cache) SetResolvedPURL(purl, resolved string) {
	c.mu.Lock()
	c.ResolvedPURLs[purl] = resolved
	dirStore := c.dirStorePath
	c.mu.Unlock()

	if dirStore != "" {
		_ = c.writeDirEntry(purl, dirEntry{PURL: purl, ResolvedPURL: resolved})
	}
}

// GetCopyright retrieves a copyright notice from the cache.
func (c *Cache) GetCopyright(purl string) (string, bool) {
	c.mu.RLock()
	val, ok := c.Copyrights[purl]
	dirStore := c.dirStorePath
	c.mu.RUnlock()

	if ok {
		return val, true
	}

	if dirStore != "" {
		if entry, err := c.readDirEntry(purl); err == nil && entry.Copyright != "" {
			c.SetCopyright(purl, entry.Copyright)
			return entry.Copyright, true
		}
	}

	return "", false
}

// SetCopyright stores a copyright in the cache.
func (c *Cache) SetCopyright(purl, copyright string) {
	c.mu.Lock()
	c.Copyrights[purl] = copyright
	dirStore := c.dirStorePath
	c.mu.Unlock()

	if dirStore != "" {
		_ = c.writeDirEntry(purl, dirEntry{PURL: purl, Copyright: copyright})
	}
}

// IsNegative checks if a PURL is currently cached as having no copyright within the given TTL.
// If ttl is 0, DefaultNegativeTTL (7 days) is used.
func (c *Cache) IsNegative(purl string, ttl time.Duration) bool {
	if ttl == 0 {
		ttl = DefaultNegativeTTL
	}
	if ttl < 0 {
		return false // Explicitly expired
	}

	c.mu.RLock()
	ts, ok := c.NegativeLookups[purl]
	c.mu.RUnlock()

	if !ok {
		return false
	}

	return time.Since(time.Unix(ts, 0)) < ttl
}

// SetNegative records a negative lookup (no copyright found) to prevent repeated API calls.
func (c *Cache) SetNegative(purl string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.NegativeLookups[purl] = time.Now().Unix()
}

// GetLicense retrieves a license from the cache.
func (c *Cache) GetLicense(purl string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.Licenses[purl]
	return val, ok
}

// SetLicense stores a license in the cache.
func (c *Cache) SetLicense(purl, license string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Licenses[purl] = license
}

// Content-addressed directory storage types and helpers
type dirEntry struct {
	PURL         string `json:"purl"`
	ResolvedPURL string `json:"resolved_purl,omitempty"`
	Copyright    string `json:"copyright,omitempty"`
	License      string `json:"license,omitempty"`
	Timestamp    int64  `json:"timestamp"`
}

func (c *Cache) hashKey(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:])
}

func (c *Cache) readDirEntry(purl string) (*dirEntry, error) {
	hash := c.hashKey(purl)
	path := filepath.Join(c.dirStorePath, "entries", hash+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entry dirEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (c *Cache) writeDirEntry(purl string, entry dirEntry) error {
	hash := c.hashKey(purl)
	entry.Timestamp = time.Now().Unix()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	entriesDir := filepath.Join(c.dirStorePath, "entries")
	tmpFile, err := os.CreateTemp(entriesDir, ".entry-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	dest := filepath.Join(entriesDir, hash+".json")
	return os.Rename(tmpName, dest)
}
