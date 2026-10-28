package enricher

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bonjoski/bomhound/internal/cache"
	"github.com/bonjoski/bomhound/internal/config"
	"github.com/bonjoski/bomhound/internal/parser"
)

// CopyrightFinder defines the interface for single-copyright lookups.
type CopyrightFinder interface {
	FindCopyright(ctx context.Context, purl string) (string, error)
}

// MultiCopyrightFinder defines the interface for extracting all distinct copyright notices.
type MultiCopyrightFinder interface {
	FindCopyrights(ctx context.Context, purl string) ([]string, error)
}

// RepoResolver defines the interface for resolving repository URLs.
type RepoResolver interface {
	ResolveRepoURL(purl string) (string, error)
}

// ResolverFunc allows using a function as a RepoResolver.
type ResolverFunc func(purl string) (string, error)

func (f ResolverFunc) ResolveRepoURL(purl string) (string, error) {
	return f(purl)
}

// Enricher encapsulates the SBOM enrichment logic.
type Enricher struct {
	Finder   CopyrightFinder
	Resolver RepoResolver
	Workers  int
	Cache    *cache.Cache
	Config   *config.Config
}

// NewEnricher creates a new Enricher.
func NewEnricher(finder CopyrightFinder, resolver RepoResolver, workers int, c *cache.Cache, cfg *config.Config) *Enricher {
	if workers <= 0 {
		workers = 5 // Default concurrency
	}
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Enricher{
		Finder:   finder,
		Resolver: resolver,
		Workers:  workers,
		Cache:    c,
		Config:   cfg,
	}
}

// Stats holds enrichment statistics.
type Stats struct {
	Found   int
	Missing int

	// Failure categories
	SkippedExcluded  int // Skipped via user exclusion rules
	SkippedNonGitHub int // Not on GitHub
	SkippedRPM       int // RPM packages
	FailedCopyright  int // GitHub repo but no copyright found
	FailedResolution int // Could not resolve to GitHub
}

// Enrich parses the input SBOM, finds copyrights, and saves the result safely.
func (e *Enricher) Enrich(ctx context.Context, inputPath, outputPath string) (*Stats, error) {
	bom, format, err := parser.ParseSBOM(inputPath)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	stats, err := e.EnrichBOM(ctx, bom)
	if err != nil {
		return nil, err
	}

	if err := parser.SaveSBOM(bom, format, outputPath); err != nil {
		return nil, fmt.Errorf("saving SBOM: %w", err)
	}

	return stats, nil
}

// EnrichStream reads a CycloneDX SBOM from an io.Reader, enriches it, and writes
// the output directly to an io.Writer (e.g. for UNIX pipeline streaming).
func (e *Enricher) EnrichStream(ctx context.Context, r io.Reader, w io.Writer) (*Stats, error) {
	bom, format, err := parser.ParseSBOMReader(r)
	if err != nil {
		return nil, fmt.Errorf("decoding SBOM from stream: %w", err)
	}

	stats, err := e.EnrichBOM(ctx, bom)
	if err != nil {
		return nil, err
	}

	if err := parser.EncodeSBOM(bom, format, w); err != nil {
		return nil, fmt.Errorf("encoding enriched SBOM to stream: %w", err)
	}

	return stats, nil
}

// EnrichBOM enriches an in-memory CycloneDX BOM with copyright evidence.
func (e *Enricher) EnrichBOM(ctx context.Context, bom *cdx.BOM) (*Stats, error) {
	componentsCount := 0
	if bom.Components != nil {
		componentsCount = len(*bom.Components)
	}

	if componentsCount == 0 {
		return &Stats{}, nil
	}

	// Fixed worker pool to prevent goroutine explosions and memory blowouts
	var (
		statsMu          sync.Mutex
		found            int
		missing          int
		skippedExcluded  int
		skippedNonGitHub int
		skippedRPM       int
		failedCopyright  int
		failedResolution int
	)

	jobs := make(chan int, componentsCount)
	var wg sync.WaitGroup

	for w := 0; w < e.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case idx, ok := <-jobs:
					if !ok {
						return
					}

					comp := &(*bom.Components)[idx]
					notices, category, err := e.processComponentWithCategory(ctx, comp)

					statsMu.Lock()
					if err != nil {
						missing++
						failedCopyright++
					} else if len(notices) > 0 {
						found++
						// Populate Evidence.Copyright per CycloneDX spec
						var evidenceList []cdx.Copyright
						for _, notice := range notices {
							evidenceList = append(evidenceList, cdx.Copyright{Text: notice})
						}

						if comp.Evidence == nil {
							comp.Evidence = &cdx.Evidence{}
						}
						comp.Evidence.Copyright = &evidenceList

						// Populate declared copyright if not already present
						if comp.Copyright == "" {
							comp.Copyright = notices[0]
						}

						slog.Debug("Found copyright", "component", comp.Name, "notices", len(notices))
					} else {
						missing++
					}

					// Track category
					switch category {
					case "excluded":
						skippedExcluded++
					case "non-github":
						skippedNonGitHub++
					case "rpm":
						skippedRPM++
					case "no-copyright":
						failedCopyright++
					case "no-resolution":
						failedResolution++
					}
					statsMu.Unlock()
				}
			}
		}()
	}

	// Dispatch jobs
	for i := 0; i < componentsCount; i++ {
		jobs <- i
	}
	close(jobs)

	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	slog.Info("Enrichment complete", "found", found, "missing", missing)

	return &Stats{
		Found:            found,
		Missing:          missing,
		SkippedExcluded:  skippedExcluded,
		SkippedNonGitHub: skippedNonGitHub,
		SkippedRPM:       skippedRPM,
		FailedCopyright:  failedCopyright,
		FailedResolution: failedResolution,
	}, nil
}
