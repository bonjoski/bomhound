package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/bonjoski/bomhound/internal/auth"
	"github.com/bonjoski/bomhound/internal/cache"
	"github.com/bonjoski/bomhound/internal/config"
	"github.com/bonjoski/bomhound/internal/copyright"
	"github.com/bonjoski/bomhound/internal/enricher"
	"github.com/bonjoski/bomhound/internal/resolver"
	"github.com/bonjoski/bomhound/internal/utils"
	"github.com/bonjoski/bomhound/pkg/bomhound"
	"golang.org/x/term"
)

func main() {
	// Direct slog output to Stderr so Stdout can be reserved exclusively for clean SBOM streams
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	resetToken := flag.Bool("reset-token", false, "Reset the GitHub token in the keyring")
	outputDir := flag.String("output-dir", "output", "Directory to save enriched SBOMs")
	inPlace := flag.Bool("in-place", false, "Overwrite input SBOM files in-place")
	concurrency := flag.Int("concurrency", 5, "Number of concurrent workers")
	configPath := flag.String("config", "", "Path to configuration file (.bomhound.yaml)")
	flag.Parse()

	args := flag.Args()
	filePath := "."
	if len(args) > 0 {
		filePath = args[0]
	}

	// Detect if input should be read from STDIN (pipe mode)
	isStdin := filePath == "-" || (len(args) == 0 && !term.IsTerminal(int(os.Stdin.Fd())))

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Handle token reset
	if *resetToken {
		if err := auth.ClearToken(); err != nil {
			slog.Warn("Failed to clear token from keyring", "error", err)
		} else {
			slog.Info("Token cleared from keyring. You will be prompted to enter a new one.")
		}
	}

	// Get GitHub Token
	token, err := auth.GetGitHubToken()
	if err != nil {
		slog.Error("Error getting GitHub token", "error", err)
		os.Exit(2)
	}

	// Initialize Cache with pre-embedded mappings and atomic persistence
	c, err := bomhound.GetDefaultCache()
	if err != nil || c == nil {
		c = cache.New()
	}
	if cfg.Cache.Dir != "" {
		if err := c.SetDirStore(cfg.Cache.Dir); err != nil {
			slog.Warn("Failed to initialize cache directory", "dir", cfg.Cache.Dir, "error", err)
		}
	}
	cachePath := ".bomhound-cache.json"
	if err := c.Load(cachePath); err != nil {
		slog.Warn("Failed to load local cache", "error", err)
	}
	defer func() {
		if err := c.Save(cachePath); err != nil {
			slog.Error("Failed to save cache", "error", err)
		}
	}()

	// Initialize Dependencies
	finder := copyright.NewFinder(token)
	res := enricher.ResolverFunc(resolver.ResolveRepoURL)

	// Initialize Enricher
	e := enricher.NewEnricher(finder, res, *concurrency, c, cfg)
	ctx := context.Background()

	// 1. Process STDIN Stream Mode (UNIX Pipe)
	if isStdin {
		stats, err := e.EnrichStream(ctx, os.Stdin, os.Stdout)
		if err != nil {
			slog.Error("Stream enrichment failed", "error", err)
			os.Exit(1)
		}
		slog.Info("Stream enrichment complete", "found", stats.Found, "missing", stats.Missing)

		// Compliance gates
		if cfg.Compliance.FailOnMissing && stats.Missing > 0 {
			slog.Error("Compliance policy failed: missing copyrights detected", "missing", stats.Missing)
			os.Exit(5)
		}
		return
	}

	// 2. Process File / Directory Mode
	inputFiles, err := utils.FindSBOMFiles(filePath)
	if err != nil {
		slog.Error("Failed to find input files", "error", err)
		os.Exit(1)
	}

	if len(inputFiles) == 0 {
		slog.Error("No .json or .xml SBOM files found")
		os.Exit(1)
	}
	slog.Info("Found input files", "count", len(inputFiles))

	// Aggregated Statistics
	totalFound := 0
	totalMissing := 0

	type fileStats struct {
		filename string
		found    int
		missing  int
		stats    *enricher.Stats
	}
	var perFileStats []fileStats

	for _, inputPath := range inputFiles {
		filename := filepath.Base(inputPath)
		var outputPath string
		if *inPlace {
			outputPath = inputPath
		} else {
			outputPath = filepath.Join(*outputDir, filename)
		}

		// Run Enrichment
		stats, err := e.Enrich(ctx, inputPath, outputPath)
		if err != nil {
			slog.Error("Error enriching SBOM", "file", inputPath, "error", err)
			continue
		}

		totalFound += stats.Found
		totalMissing += stats.Missing
		perFileStats = append(perFileStats, fileStats{
			filename: filename,
			found:    stats.Found,
			missing:  stats.Missing,
			stats:    stats,
		})
		slog.Info("Saved enriched SBOM", "path", outputPath)
	}

	// Display per-file statistics on Stderr
	fmt.Fprintln(os.Stderr, "\n========================================")
	fmt.Fprintln(os.Stderr, "Per-SBOM Statistics")
	fmt.Fprintln(os.Stderr, "========================================")
	for _, fs := range perFileStats {
		total := fs.found + fs.missing
		successRate := 0.0
		if total > 0 {
			successRate = float64(fs.found) / float64(total) * 100
		}
		fmt.Fprintf(os.Stderr, "%-30s  Found: %4d  Missing: %4d  Success: %5.1f%%\n",
			fs.filename, fs.found, fs.missing, successRate)

		if fs.missing > 0 {
			if fs.stats.SkippedExcluded > 0 {
				fmt.Fprintf(os.Stderr, "  └─ Skipped (Excluded Policy): %4d\n", fs.stats.SkippedExcluded)
			}
			if fs.stats.SkippedRPM > 0 {
				fmt.Fprintf(os.Stderr, "  └─ Skipped (RPM):             %4d\n", fs.stats.SkippedRPM)
			}
			if fs.stats.SkippedNonGitHub > 0 {
				fmt.Fprintf(os.Stderr, "  └─ Skipped (Non-GitHub):      %4d\n", fs.stats.SkippedNonGitHub)
			}
			if fs.stats.FailedCopyright > 0 {
				fmt.Fprintf(os.Stderr, "  └─ Failed (No Copyright):     %4d\n", fs.stats.FailedCopyright)
			}
			if fs.stats.FailedResolution > 0 {
				fmt.Fprintf(os.Stderr, "  └─ Failed (No Resolution):    %4d\n", fs.stats.FailedResolution)
			}
		}
	}

	fmt.Fprintln(os.Stderr, "\n========================================")
	fmt.Fprintln(os.Stderr, "Combined Statistics")
	fmt.Fprintln(os.Stderr, "========================================")
	fmt.Fprintf(os.Stderr, "Total Copyrights Found:   %d\n", totalFound)
	fmt.Fprintf(os.Stderr, "Total Copyrights Missing: %d\n", totalMissing)
	total := totalFound + totalMissing
	rate := 0.0
	if total > 0 {
		rate = float64(totalFound) / float64(total) * 100
		fmt.Fprintf(os.Stderr, "Overall Success Rate:     %.1f%%\n", rate)
	}

	// Compliance Gate Checks (Exit code 5)
	if cfg.Compliance.FailOnMissing && totalMissing > 0 {
		slog.Error("Compliance policy failed: missing copyrights detected", "missing", totalMissing)
		os.Exit(5)
	}
	if cfg.Compliance.MinCoveragePercent > 0 && total > 0 && rate < cfg.Compliance.MinCoveragePercent {
		slog.Error("Compliance policy failed: coverage below required threshold", "rate", rate, "min", cfg.Compliance.MinCoveragePercent)
		os.Exit(5)
	}
}
