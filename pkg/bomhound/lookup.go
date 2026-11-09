package bomhound

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/bonjoski/bomhound/internal/cache"
	"github.com/bonjoski/bomhound/internal/resolver"
)

//go:embed .sbom-cache.json
var embeddedCacheData []byte

var (
	defaultCacheMu  sync.Mutex
	defaultCache    *cache.Cache
	defaultCacheErr error
)

func resetDefaultCacheForTest() {
	defaultCacheMu.Lock()
	defer defaultCacheMu.Unlock()
	defaultCache = nil
	defaultCacheErr = nil
}

var (
	apacheLicenseRe = regexp.MustCompile(`(?i)\b(apache(?:\s+license)?(?:\s*,?\s*version\s*2(?:\.0)?|\s+2\.0|-2\.0)|apache-2\.0)\b`)
	mitLicenseRe    = regexp.MustCompile(`(?i)\b(mit\s+license|mit)\b`)
	bsd3LicenseRe   = regexp.MustCompile(`(?i)\bbsd[- ]3[- ]clause\b`)
	bsd2LicenseRe   = regexp.MustCompile(`(?i)\bbsd[- ]2[- ]clause\b`)
	iscLicenseRe    = regexp.MustCompile(`(?i)\b(isc\s+license|isc)\b`)
	mplLicenseRe    = regexp.MustCompile(`(?i)\b(mozilla\s+public\s+license|mpl-2\.0|mpl\s+2\.0|mpl)\b`)
	gplLicenseRe    = regexp.MustCompile(`(?i)\b(gnu\s+general\s+public\s+license|general\s+public\s+license|gpl-3\.0(?:-only|-or-later)?|gplv3|gpl)\b`)
)

// GetDefaultCache returns the singleton cache backed by embedded data and trusted user cache
// under ~/.cache/bomhound. Untrusted CWD or parent-directory .sbom-cache.json files are never auto-loaded.
func GetDefaultCache() (*cache.Cache, error) {
	defaultCacheMu.Lock()
	defer defaultCacheMu.Unlock()
	if defaultCache == nil && defaultCacheErr == nil {
		c, err := newTrustedCache()
		if err != nil {
			defaultCacheErr = err
		} else {
			defaultCache = c
		}
	}

	return defaultCache, defaultCacheErr
}

func newTrustedCache() (*cache.Cache, error) {
	c := cache.New()

	if len(embeddedCacheData) > 0 {
		if err := json.Unmarshal(embeddedCacheData, c); err != nil {
			return nil, fmt.Errorf("unmarshaling embedded sbom cache: %w", err)
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
		if c.NegativeLookups == nil {
			c.NegativeLookups = make(map[string]int64)
		}
	}

	// Overlay trusted user-home cache files only (~/.cache/bomhound/*).
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		trustedDir := filepath.Join(home, ".cache", "bomhound")
		for _, name := range []string{"cache.json", ".sbom-cache.json"} {
			candidate := filepath.Join(trustedDir, name)
			if lfi, statErr := os.Lstat(candidate); statErr == nil && lfi.Mode().IsRegular() {
				if loadErr := c.Load(candidate); loadErr != nil {
					continue
				}
			}
		}
	}

	return c, nil
}

// LookupLicenses performs strictly offline, zero-network in-process license lookup for the provided PURLs.
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

// LookupLicensesWithCache performs strictly offline license lookup using a specific cache instance.
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

// resolveLicense resolves the SPDX license identifier offline without making any network calls.
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

	// 4. Ecosystem & prefix stripping (strictly offline map lookups only)
	candidate := trimmed
	if withoutVersion != "" {
		candidate = withoutVersion
	}

	if strings.HasPrefix(candidate, "pkg:") {
		idx := strings.Index(candidate, "/")
		if idx != -1 && idx+1 < len(candidate) {
			pkgPath := candidate[idx+1:]
			if lic, ok := c.GetLicense(pkgPath); ok && lic != "" {
				return lic
			}

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

	// 5. Copyright heuristic fallback using strict word-boundary matching
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

// inferLicenseFromText inspects copyright/license text using word-boundary tokens
// so entity names like "Acme Limited", "Committer", "Cisco", or "Example" never false-match.
func inferLicenseFromText(text string) string {
	switch {
	case apacheLicenseRe.MatchString(text):
		return "Apache-2.0"
	case bsd3LicenseRe.MatchString(text):
		return "BSD-3-Clause"
	case bsd2LicenseRe.MatchString(text):
		return "BSD-2-Clause"
	case mitLicenseRe.MatchString(text):
		return "MIT"
	case iscLicenseRe.MatchString(text):
		return "ISC"
	case mplLicenseRe.MatchString(text):
		return "MPL-2.0"
	case gplLicenseRe.MatchString(text):
		return "GPL-3.0-only"
	default:
		return ""
	}
}
