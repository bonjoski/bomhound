package enricher

import (
	"context"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bonjoski/bomhound/internal/resolver"
)

func isGitHubRepo(urlOrPURL string) bool {
	return strings.Contains(urlOrPURL, "github.com") || strings.HasPrefix(urlOrPURL, "pkg:github/")
}

func (e *Enricher) processComponentWithCategory(ctx context.Context, comp *cdx.Component) ([]string, string, error) {
	purl := comp.PackageURL

	// 1. Check user policy exclusions
	if e.Config != nil {
		if excluded, _ := e.Config.IsExcluded(purl, comp.Name); excluded {
			return nil, "excluded", nil
		}
	}

	// Default skip for non-library or RPM packages if not already excluded
	if strings.HasPrefix(purl, "pkg:rpm/") {
		return nil, "rpm", nil
	}

	if purl == "" {
		return nil, "no-purl", nil
	}

	// 2. Resolve Target PURL
	targetPURL := purl

	// Check cache for resolved URL
	if val, ok := e.Cache.GetResolvedPURL(purl); ok {
		targetPURL = val
	} else {
		// Try to resolve via PURL if not already a GitHub repo
		if !isGitHubRepo(purl) {
			// Check custom vanity mappings from config first
			resolved := false
			if e.Config != nil && len(e.Config.VanityURLs) > 0 {
				for prefix, target := range e.Config.VanityURLs {
					cleanPurl := strings.TrimPrefix(purl, "pkg:golang/")
					if strings.HasPrefix(cleanPurl, prefix) {
						targetPURL = "pkg:github/" + target + strings.TrimPrefix(cleanPurl, prefix)
						resolved = true
						break
					}
				}
			}

			// Try Go vanity URL resolution for golang packages
			if !resolved && strings.HasPrefix(purl, "pkg:golang/") {
				importPath := strings.TrimPrefix(purl, "pkg:golang/")
				var version string
				if idx := strings.Index(importPath, "@"); idx != -1 {
					version = importPath[idx:]
					importPath = importPath[:idx]
				}

				if githubRepo, ok := resolver.ResolveGoVanityURL(importPath); ok {
					githubRepo = strings.TrimPrefix(githubRepo, "github.com/")
					targetPURL = "pkg:github/" + githubRepo + version
				}
			}

			// If still not GitHub, try registry resolution
			if !isGitHubRepo(targetPURL) {
				resolvedURL, err := e.Resolver.ResolveRepoURL(purl)
				if err == nil && isGitHubRepo(resolvedURL) {
					cleanURL := strings.TrimPrefix(resolvedURL, "github.com/")
					targetPURL = "pkg:github/" + cleanURL
				}
			}
		}

		// If still not GitHub, check external references
		if !isGitHubRepo(targetPURL) && comp.ExternalReferences != nil {
			for _, ref := range *comp.ExternalReferences {
				refType := string(ref.Type)
				if (refType == "vcs" || refType == "source" || refType == "website" || refType == "distribution") && isGitHubRepo(ref.URL) {
					url := ref.URL
					url = strings.TrimPrefix(url, "https://")
					url = strings.TrimPrefix(url, "http://")
					url = strings.TrimPrefix(url, "git+")
					url = strings.TrimSuffix(url, ".git")

					parts := strings.Split(url, "/")
					if len(parts) >= 3 && parts[0] == "github.com" {
						targetPURL = "pkg:github/" + parts[1] + "/" + parts[2]
						break
					}
				}
			}
		}

		e.Cache.SetResolvedPURL(purl, targetPURL)
	}

	if !isGitHubRepo(targetPURL) {
		return nil, "non-github", nil
	}

	// 3. Find Copyright
	// Check cache (full targetPURL and version-stripped)
	lookupKeys := []string{targetPURL}
	if idx := strings.LastIndex(targetPURL, "@"); idx != -1 {
		lookupKeys = append(lookupKeys, targetPURL[:idx])
	}

	for _, k := range lookupKeys {
		if val, ok := e.Cache.GetCopyright(k); ok {
			if val != "" {
				return []string{val}, "", nil
			}
			return nil, "no-copyright", nil
		}
	}

	// Try multi-copyright lookup
	var notices []string
	if multiFinder, ok := e.Finder.(MultiCopyrightFinder); ok {
		var err error
		notices, err = multiFinder.FindCopyrights(ctx, targetPURL)
		if err != nil {
			return nil, "no-copyright", err
		}
	} else {
		cpy, err := e.Finder.FindCopyright(ctx, targetPURL)
		if err != nil {
			return nil, "no-copyright", err
		}
		if cpy != "" {
			notices = []string{cpy}
		}
	}

	if len(notices) > 0 {
		e.Cache.SetCopyright(targetPURL, notices[0])
		if idx := strings.LastIndex(targetPURL, "@"); idx != -1 {
			e.Cache.SetCopyright(targetPURL[:idx], notices[0])
		}
		return notices, "", nil
	}

	return nil, "no-copyright", nil
}
