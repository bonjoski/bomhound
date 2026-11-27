package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bonjoski/bomhound/internal/auth"
	"github.com/bonjoski/bomhound/internal/cache"
	"github.com/bonjoski/bomhound/internal/config"
	"github.com/bonjoski/bomhound/internal/copyright"
	"github.com/bonjoski/bomhound/internal/enricher"
	"github.com/bonjoski/bomhound/internal/parser"
	"github.com/bonjoski/bomhound/internal/resolver"
	"github.com/bonjoski/bomhound/pkg/aibom"
	"github.com/bonjoski/bomhound/pkg/bomhound"
)

func runEnrich(args []string) int {
	if len(args) > 0 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		printEnrichUsage()
		return 0
	}

	fs := flag.NewFlagSet("bomhound enrich", flag.ContinueOnError)
	inputPath := fs.String("input", "", "Path to input CycloneDX SBOM JSON/XML file (or '-' for stdin)")
	outputPath := fs.String("output", "", "Path to write enriched CycloneDX SBOM (default: stdout when stdin, else required unless --in-place)")
	inPlace := fs.Bool("in-place", false, "Overwrite input SBOM file in-place")
	aiBomPath := fs.String("ai-bom", "", "Optional path to .ai-bom.yaml for CycloneDX 1.6 AI-BOM component injection")
	rootDir := fs.String("root", "", "Workspace root directory for os.OpenRoot confinement of --ai-bom")
	offline := fs.Bool("offline", false, "Skip remote copyright lookups (inject AI-BOM metadata offline)")
	concurrency := fs.Int("concurrency", 5, "Number of concurrent workers")
	configPath := fs.String("config", "", "Path to configuration file (.bomhound.yaml)")
	cacheFlag := fs.String("cache", "", "Path to cache JSON file")
	locksmithKey := fs.String("locksmith-key", "", "Key name for GitHub token in Locksmith vault")
	tokenStdin := fs.Bool("token-stdin", false, "Read GitHub token from standard input")

	if err := fs.Parse(reorderFlagsBeforePositional(args, map[string]bool{
		"in-place": true, "offline": true, "token-stdin": true,
	})); err != nil {
		return 1
	}

	inFile := *inputPath
	if inFile == "" && fs.NArg() > 0 {
		inFile = fs.Arg(0)
	}
	if inFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --input <sbom.cdx.json> (or positional SBOM path) is required")
		printEnrichUsage()
		return 1
	}

	var aiCfg *aibom.AIBOMConfig
	if strings.TrimSpace(*aiBomPath) != "" {
		var err error
		aiCfg, err = loadAIBOMConfined(*rootDir, *aiBomPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading AI-BOM config: %v\n", err)
			return 1
		}
	}

	outFile := *outputPath
	if *inPlace && inFile != "-" {
		outFile = inFile
	}

	// Parse input SBOM (from stdin or file).
	cdxBOM, cdxFormat, err := parseEnrichInput(inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing input SBOM: %v\n", err)
		return 1
	}

	// Online copyright enrichment unless --offline is specified.
	if !*offline {
		cfg, err := config.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			return 1
		}
		key := *locksmithKey
		if key == "" {
			key = cfg.Auth.LocksmithKey
		}
		ctx := context.Background()
		token, err := auth.GetGitHubToken(ctx, auth.TokenOptions{
			LocksmithKey: key,
			TokenStdin:   *tokenStdin,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error authenticating (pass --offline to inject --ai-bom without GitHub lookups): %v\n", err)
			return 2
		}

		c, err := bomhound.GetDefaultCache()
		if err != nil || c == nil {
			c = cache.New()
		}
		if *cacheFlag != "" {
			if err := c.Load(*cacheFlag); err != nil {
				slog.Warn("Failed to load local cache", "error", err)
			}
			defer func() {
				if err := c.Save(*cacheFlag); err != nil {
					slog.Error("Failed to save cache", "error", err)
				}
			}()
		}

		finder := copyright.NewFinder(token)
		res := enricher.ResolverFunc(resolver.ResolveRepoURL)
		e := enricher.NewEnricher(finder, res, *concurrency, c, cfg)
		stats, err := e.EnrichBOM(ctx, cdxBOM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error enriching SBOM: %v\n", err)
			return 1
		}
		slog.Info("Copyright enrichment complete", "found", stats.Found, "missing", stats.Missing)
	}

	// Inject CycloneDX 1.6 AI-BOM components without mutating existing hashes or copyrights.
	if aiCfg != nil {
		if err := aibom.InjectAIBOM(cdxBOM, aiCfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error injecting AI-BOM metadata: %v\n", err)
			return 1
		}
	}

	if outFile == "" || outFile == "-" {
		if err := parser.EncodeSBOM(cdxBOM, cdxFormat, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding enriched SBOM: %v\n", err)
			return 1
		}
		return 0
	}

	if err := parser.SaveSBOM(cdxBOM, cdxFormat, outFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving enriched SBOM: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Enriched SBOM saved to %s\n", filepath.Clean(outFile))
	return 0
}

func printEnrichUsage() {
	fmt.Println(`bomhound enrich — CycloneDX Legal Attribution & AI-BOM Enrichment

Usage:
  bomhound enrich --input <sbom.cdx.json> [--ai-bom .ai-bom.yaml] --output <enriched.cdx.json>

Flags:
  --input            Path to input CycloneDX SBOM file (or '-' for stdin)
  --output           Path to output enriched CycloneDX SBOM (default: stdout)
  --in-place         Overwrite input SBOM in-place
  --ai-bom           Path to repo-local .ai-bom.yaml (confined via os.OpenRoot)
  --root             Workspace root directory for os.OpenRoot confinement (default: cwd)
  --offline          Skip remote copyright lookups and inject AI-BOM metadata offline
  --concurrency      Number of concurrent copyright workers (default: 5)
  --config           Path to .bomhound.yaml configuration file
  --cache            Path to cache JSON file
  --locksmith-key    Key name for GitHub token in Locksmith vault
  --token-stdin      Read GitHub token from standard input`)
}

func loadAIBOMConfined(rootDir, aiBomPath string) (*aibom.AIBOMConfig, error) {
	// Reject explicit '..' traversal segments before any resolution.
	for _, seg := range strings.Split(strings.ReplaceAll(aiBomPath, "\\", "/"), "/") {
		if seg == ".." {
			return nil, fmt.Errorf("%w: parent traversal '..' not allowed in --ai-bom path %q", aibom.ErrPathTraversal, aiBomPath)
		}
	}

	if strings.TrimSpace(rootDir) != "" {
		return aibom.LoadAIBOMConfig(rootDir, aiBomPath)
	}

	if filepath.IsAbs(aiBomPath) {
		cleaned := filepath.Clean(aiBomPath)
		return aibom.LoadAIBOMConfig(filepath.Dir(cleaned), filepath.Base(cleaned))
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	return aibom.LoadAIBOMConfig(cwd, aiBomPath)
}

func parseEnrichInput(inFile string) (*cdx.BOM, cdx.BOMFileFormat, error) {
	if inFile == "-" {
		return parser.ParseSBOMReader(os.Stdin)
	}
	return parser.ParseSBOM(inFile)
}

// Helper utilities shared by CLI subcommands.

func readRegularFileBounded(path string, maxBytes int64) ([]byte, error) {
	cleaned := filepath.Clean(path)
	fi, err := os.Lstat(cleaned)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read symlink: %s", cleaned)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", cleaned)
	}
	if fi.Size() > maxBytes {
		return nil, fmt.Errorf("file %s exceeds maximum allowed size (%d bytes)", cleaned, maxBytes)
	}
	f, err := os.Open(cleaned)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds maximum allowed size (%d bytes)", cleaned, maxBytes)
	}
	return data, nil
}

func writeFileAtomicNoSymlink(outputPath string, data []byte, perm os.FileMode) error {
	cleaned := filepath.Clean(outputPath)
	if fi, err := os.Lstat(cleaned); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write to symlink: %s", cleaned)
	}
	dir := filepath.Dir(cleaned)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".bomhound-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if fi, err := os.Lstat(cleaned); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink: %s", cleaned)
	}
	if err := os.Rename(tmpName, cleaned); err != nil {
		return err
	}
	renamed = true
	return nil
}

// reorderFlagsBeforePositional allows Go's flag.FlagSet to accept flags placed after
// positional arguments (e.g., `bomhound bundle --verify dist/bundle.tar.gz --pubkey pub.pem`).
func reorderFlagsBeforePositional(args []string, boolFlags map[string]bool) []string {
	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			name := strings.TrimLeft(arg, "-")
			if !boolFlags[name] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positional = append(positional, arg)
		}
	}
	return append(flags, positional...)
}
