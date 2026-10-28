package bomhound

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bonjoski/bomhound/internal/cache"
	"github.com/bonjoski/bomhound/internal/resolver"
)

//go:embed .sbom-cache.json
var embeddedCacheData []byte

var (
	defaultCache     *cache.Cache
	defaultCacheOnce sync.Once
	defaultCacheErr  error
)

// GetDefaultCache returns the singleton cache backed by embedded data and on-disk files.
// It searches the filesystem first (respecting SBOM_CACHE_PATH and local files)
// and falls back to embedded cache data for zero-latency in-process lookups.
func GetDefaultCache() (*cache.Cache, error) {
	defaultCacheOnce.Do(func() {
		c := cache.New()

		// Candidates for cache file on disk
		candidates := []string{}
		if envPath := os.Getenv("SBOM_CACHE_PATH"); envPath != "" {
			candidates = append(candidates, envPath)
		}
		candidates = append(candidates,
			".sbom-cache.json",
			"../.sbom-cache.json",
			"../../.sbom-cache.json",
		)

		// Try finding the cache file in directory tree
		loaded := false
		for _, path := range candidates {
			if stat, err := os.Stat(path); err == nil && !stat.IsDir() {
				if err := c.Load(path); err == nil {
					loaded = true
					break
				}
			}
		}

		// Also check current directory walk upwards up to 5 levels
		if !loaded {
			dir, err := os.Getwd()
			if err == nil {
				curr := dir
				for i := 0; i < 5; i++ {
					target := filepath.Join(curr, ".sbom-cache.json")
					if stat, err := os.Stat(target); err == nil && !stat.IsDir() {
						if err := c.Load(target); err == nil {
							loaded = true
							break
						}
					}
					parent := filepath.Dir(curr)
					if parent == curr {
						break
					}
					curr = parent
				}
			}
		}

		// Fallback to embedded cache
		if !loaded && len(embeddedCacheData) > 0 {
			if err := json.Unmarshal(embeddedCacheData, c); err != nil {
				defaultCacheErr = fmt.Errorf("unmarshaling embedded sbom cache: %w", err)
				return
			}
			if c.ResolvedPURLs == nil {
				c.ResolvedPURLs = make(map[string]string)
			}
			if c.Copyrights == nil {
				c.Copyrights = make(map[string]string)
			}
			if c.Licenses == nil {
				c.Licenses = make(map[string]string)
			}
		}

		defaultCache = c
	})

	return defaultCache, defaultCacheErr
}

// LookupLicenses performs in-process license lookup for the provided PURLs or package names.
// It is backed by .sbom-cache.json to verify licenses against allowlists with zero network latency.
func LookupLicenses(ctx context.Context, purls []string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	c, err := GetDefaultCache()
	if err != nil {
		return nil, fmt.Errorf("loading sbom cache: %w", err)
	}

	return LookupLicensesWithCache(ctx, purls, c)
}

// LookupLicensesWithCache performs license lookup using a specific cache instance.
func LookupLicensesWithCache(ctx context.Context, purls []string, c *cache.Cache) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	if c == nil {
		return nil, fmt.Errorf("nil cache provided")
	}

	results := make(map[string]string, len(purls))
	for _, p := range purls {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context cancelled: %w", err)
		}

		results[p] = resolveLicense(c, p)
	}

	return results, nil
}

// resolveLicense resolves the SPDX license identifier for a given package name or purl.
func resolveLicense(c *cache.Cache, purl string) string {
	trimmed := strings.TrimSpace(purl)
	if trimmed == "" {
		return "UNKNOWN"
	}

	// 1. Direct cache lookup
	if lic, ok := c.GetLicense(trimmed); ok && lic != "" {
		return lic
	}

	// 2. Resolved PURL direct lookup
	if resolved, ok := c.GetResolvedPURL(trimmed); ok && resolved != "" {
		if lic, ok := c.GetLicense(resolved); ok && lic != "" {
			return lic
		}
	}

	// 3. Version-stripped lookup
	var withoutVersion string
	if idx := strings.LastIndex(trimmed, "@"); idx != -1 {
		withoutVersion = trimmed[:idx]
		if lic, ok := c.GetLicense(withoutVersion); ok && lic != "" {
			return lic
		}
		if resolved, ok := c.GetResolvedPURL(withoutVersion); ok && resolved != "" {
			if lic, ok := c.GetLicense(resolved); ok && lic != "" {
				return lic
			}
		}
	}

	// 4. Ecosystem & prefix stripping
	candidate := trimmed
	if withoutVersion != "" {
		candidate = withoutVersion
	}

	// Remove pkg:<type>/ prefix
	if strings.HasPrefix(candidate, "pkg:") {
		idx := strings.Index(candidate, "/")
		if idx != -1 && idx+1 < len(candidate) {
			pkgPath := candidate[idx+1:]
			if lic, ok := c.GetLicense(pkgPath); ok && lic != "" {
				return lic
			}

			// Try resolving vanity URL if golang package
			if strings.HasPrefix(candidate, "pkg:golang/") {
				if repo, ok := resolver.ResolveGoVanityURL(pkgPath); ok {
					if lic, ok := c.GetLicense(repo); ok && lic != "" {
						return lic
					}
					if lic, ok := c.GetLicense("pkg:github/" + repo); ok && lic != "" {
						return lic
					}
					if lic, ok := c.GetLicense("github.com/" + repo); ok && lic != "" {
						return lic
					}
				}
			}

			// Check GitHub repo subpath matching: github.com/owner/repo[/subpath]
			if strings.HasPrefix(pkgPath, "github.com/") {
				parts := strings.Split(pkgPath, "/")
				if len(parts) >= 3 {
					repoKey := parts[1] + "/" + parts[2]
					fullRepo := "github.com/" + repoKey
					if lic, ok := c.GetLicense(fullRepo); ok && lic != "" {
						return lic
					}
					if lic, ok := c.GetLicense(repoKey); ok && lic != "" {
						return lic
					}
					if lic, ok := c.GetLicense("pkg:github/" + fullRepo); ok && lic != "" {
						return lic
					}
				}
			}
		}
	} else {
		// Non-PURL plain package name or vanity path (e.g. "golang.org/x/crypto", "anyhow")
		if repo, ok := resolver.ResolveGoVanityURL(candidate); ok {
			if lic, ok := c.GetLicense(repo); ok && lic != "" {
				return lic
			}
			if lic, ok := c.GetLicense("github.com/" + repo); ok && lic != "" {
				return lic
			}
			if lic, ok := c.GetLicense("pkg:github/" + repo); ok && lic != "" {
				return lic
			}
		}
	}

	// 5. Copyright heuristic fallback
	cpyKeys := []string{trimmed}
	if withoutVersion != "" {
		cpyKeys = append(cpyKeys, withoutVersion)
	}
	if resolved, ok := c.GetResolvedPURL(trimmed); ok {
		cpyKeys = append(cpyKeys, resolved)
	}
	for _, k := range cpyKeys {
		if cpy, ok := c.GetCopyright(k); ok && cpy != "" {
			if lic := inferLicenseFromText(cpy); lic != "" {
				return lic
			}
		}
	}

	return "UNKNOWN"
}

// inferLicenseFromText inspects copyright/license text to deduce the canonical SPDX identifier.
func inferLicenseFromText(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "apache"):
		return "Apache-2.0"
	case strings.Contains(lower, "mit license") || strings.Contains(lower, "mit"):
		return "MIT"
	case strings.Contains(lower, "bsd-3-clause") || strings.Contains(lower, "bsd 3-clause"):
		return "BSD-3-Clause"
	case strings.Contains(lower, "bsd-2-clause") || strings.Contains(lower, "bsd 2-clause"):
		return "BSD-2-Clause"
	case strings.Contains(lower, "isc"):
		return "ISC"
	case strings.Contains(lower, "mozilla") || strings.Contains(lower, "mpl"):
		return "MPL-2.0"
	case strings.Contains(lower, "general public license") || strings.Contains(lower, "gpl"):
		return "GPL-3.0-only"
	default:
		return ""
	}
}
