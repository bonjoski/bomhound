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
	"github.com/bonjoski/bomhound/pkg/ux"
	"golang.org/x/term"
)

func main() {
	// Direct slog output to Stderr so Stdout can be reserved exclusively for clean SBOM streams
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	outputDir := flag.String("output-dir", "output", "Directory to save enriched SBOMs")
	inPlace := flag.Bool("in-place", false, "Overwrite input SBOM files in-place")
	concurrency := flag.Int("concurrency", 5, "Number of concurrent workers")
	configPath := flag.String("config", "", "Path to configuration file (.bomhound.yaml)")
	cacheFlag := flag.String("cache", "", "Path to cache JSON file (defaults to ~/.cache/bomhound/cache.json)")
	locksmithKey := flag.String("locksmith-key", "", "Key name for GitHub token in Locksmith vault (overrides config)")
	tokenStdin := flag.Bool("token-stdin", false, "Read GitHub token from standard input")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.BoolVar(showVersion, "v", false, "Print version information and exit (shorthand)")
	showWhy := flag.Bool("why", false, "Show progressive-disclosure Apache-2.0 §4c / 17 U.S.C. §1202 context")
	jsonErrors := flag.Bool("json", false, "Emit structured UB-CLI-v2 FixForwardError JSON on stderr failures")

	flag.CommandLine.SetOutput(os.Stdout)
	flag.Usage = func() {
		fmt.Println(`bomhound — High-performance CycloneDX SBOM Legal Attribution Engine

Usage:
  bomhound [flags] <sbom-file-or-dir>
  cat sbom.json | bomhound [flags] > enriched.json
  bomhound explain [attribution|cyclonedx|apache-4c|dmca-1202|sbom] [--why] [--json]
  bomhound vex kernel [flags]

Subcommands:
  explain [topic]      Explain attribution, cyclonedx, apache-4c, dmca-1202, or sbom (--why / --json)
  vex kernel [flags]   Generate OpenVEX statements from microVM Kconfig and symbol tables
  version              Print version information and exit

Flags:`)
		flag.PrintDefaults()
	}

	if len(os.Args) > 1 && os.Args[1] == "vex" {
		os.Exit(runVEX(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "explain" {
		os.Exit(runExplain(os.Args[2:], os.Stdout, os.Stderr))
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("bomhound %s\n", bomhound.FormattedVersion())
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) > 0 && args[0] == "version" {
		fmt.Printf("bomhound %s\n", bomhound.FormattedVersion())
		os.Exit(0)
	}
	if len(args) > 0 && args[0] == "help" {
		flag.Usage()
		os.Exit(0)
	}
	filePath := "."
	if len(args) > 0 {
		filePath = args[0]
	}

	// Detect if input should be read from STDIN (pipe mode)
	isStdin := filePath == "-" || (len(args) == 0 && !term.IsTerminal(int(os.Stdin.Fd())))
	if err := auth.ValidateStdinMode(*tokenStdin, isStdin); err != nil {
		slog.Error("Invalid standard input flags", "error", err)
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Get GitHub Token via hardware-bound Locksmith vault (or stdin/gh fallback)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key := *locksmithKey
	if key == "" {
		key = cfg.Auth.LocksmithKey
	}

	token, err := auth.GetGitHubToken(ctx, auth.TokenOptions{
		LocksmithKey: key,
		TokenStdin:   *tokenStdin,
	})
	if err != nil {
		ffe := &ux.FixForwardError{
			Tool:           "bomhound",
			Code:           "BOMHOUND_AUTH_REQUIRED",
			Summary:        fmt.Sprintf("Authentication failed: %v", err),
			RemediationCmd: "locksmith add GH-Read",
			WhyOneLiner:    "Bomhound fetches tokens from Locksmith, --token-stdin, or `gh auth token` (never plaintext env vars).",
			DeepWhy:        "Reading GITHUB_TOKEN from ambient environment variables leaks credentials into /proc tables, subshells, and AI agent transcripts. Store a read-only PAT in Locksmith or pipe via --token-stdin in CI.",
			References:     []string{"CWE-526", "CWE-798"},
			ExitCode:       2,
		}
		_ = ffe.Render(os.Stderr, *jsonErrors, *showWhy)
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
	cachePath := *cacheFlag
	if cachePath == "" && cfg.Cache.Dir != "" {
		cachePath = filepath.Join(cfg.Cache.Dir, "cache.json")
	}
	if cachePath != "" {
		if err := c.Load(cachePath); err != nil {
			slog.Warn("Failed to load local cache", "error", err)
		}
		defer func() {
			if err := c.Save(cachePath); err != nil {
				slog.Error("Failed to save cache", "error", err)
			}
		}()
	}

	// Initialize Dependencies
	finder := copyright.NewFinder(token)
	res := enricher.ResolverFunc(resolver.ResolveRepoURL)

	// Initialize Enricher
	e := enricher.NewEnricher(finder, res, *concurrency, c, cfg)

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
		ffe := &ux.FixForwardError{
			Tool:           "bomhound",
			Code:           "BOMHOUND_NO_INPUT_FILES",
			Summary:        "No CycloneDX .json or .xml SBOM files found at target path",
			RemediationCmd: "bomhound explain sbom --why",
			WhyOneLiner:    "Pass a CycloneDX SBOM file, a directory containing SBOMs, or `-` to stream via stdin.",
			DeepWhy:        "Generate a CycloneDX SBOM first (e.g. `syft . -o cyclonedx-json=sbom.cdx.json`) and then run `bomhound --in-place sbom.cdx.json` to enrich multi-author copyrights.",
			References:     []string{"docs/use-cases/01-sbom-license-enrichment.md"},
			ExitCode:       1,
		}
		_ = ffe.Render(os.Stderr, *jsonErrors, *showWhy)
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

	fmt.Fprint(os.Stderr, "\n"+ux.FormatEnrichmentSummary(ux.EnrichmentSummary{
		FilesProcessed: len(perFileStats),
		Found:          totalFound,
		Missing:        totalMissing,
		OutputTarget:   *outputDir,
	}, *showWhy))

	// Compliance Gate Checks (Exit code 5)
	if cfg.Compliance.FailOnMissing && totalMissing > 0 {
		ffe := &ux.FixForwardError{
			Tool:           "bomhound",
			Code:           "BOMHOUND_COMPLIANCE_GATE_FAILED",
			Summary:        fmt.Sprintf("Compliance gate paused: %d component(s) missing copyright attribution", totalMissing),
			RemediationCmd: "bomhound explain attribution --why",
			WhyOneLiner:    "Missing copyright attributions can violate Apache-2.0 §4c and 17 U.S.C. §1202 redistribution rules.",
			DeepWhy:        "Review unmatched PURLs in .bomhound.yaml (add vanity_urls for custom Go domains or exclude internal private modules) and re-run bomhound.",
			References:     []string{"https://www.apache.org/licenses/LICENSE-2.0#redistribution", "https://www.law.cornell.edu/uscode/text/17/1202"},
			ExitCode:       5,
		}
		_ = ffe.Render(os.Stderr, *jsonErrors, *showWhy)
		os.Exit(5)
	}
	if cfg.Compliance.MinCoveragePercent > 0 && total > 0 && rate < cfg.Compliance.MinCoveragePercent {
		ffe := &ux.FixForwardError{
			Tool:           "bomhound",
			Code:           "BOMHOUND_COMPLIANCE_COVERAGE_BELOW_MIN",
			Summary:        fmt.Sprintf("Compliance gate paused: %.1f%% copyright coverage is below required %.1f%%", rate, cfg.Compliance.MinCoveragePercent),
			RemediationCmd: "bomhound explain apache-4c --why",
			WhyOneLiner:    "Your .bomhound.yaml enforces a minimum copyright coverage threshold for release SBOMs.",
			DeepWhy:        "Add custom vanity_urls or internal exclude rules in .bomhound.yaml to resolve remaining components before release.",
			References:     []string{"https://www.apache.org/licenses/LICENSE-2.0#redistribution"},
			ExitCode:       5,
		}
		_ = ffe.Render(os.Stderr, *jsonErrors, *showWhy)
		os.Exit(5)
	}
}
