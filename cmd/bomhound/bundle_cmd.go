package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/bomhound/pkg/cra"
	"github.com/bonjoski/bomhound/pkg/vex"
)

func runBundle(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printBundleUsage()
		return 0
	}

	fs := flag.NewFlagSet("bomhound bundle", flag.ContinueOnError)
	doCRA := fs.Bool("cra", false, "Assemble an offline EU CRA BS EN 40000-1-1 / 1-2 evidence bundle")
	doVerify := fs.Bool("verify", false, "Verify an offline EU CRA evidence bundle (.tar.gz)")
	binaryPath := fs.String("binary", "", "Path to release binary")
	sbomPath := fs.String("sbom", "", "Path to CycloneDX SBOM JSON")
	vexPath := fs.String("vex", "", "Path to DSSE-signed OpenVEX file")
	provenancePath := fs.String("provenance", "", "Path to Soulcaster SLSA .intoto.jsonl file")
	riskPath := fs.String("risk", "", "Optional path to cra-risk.yaml lifecycle risk metadata")
	aiBomPath := fs.String("ai-bom", "", "Optional path to .ai-bom.yaml metadata")
	outPath := fs.String("out", "", "Output .tar.gz bundle path")
	bundlePath := fs.String("bundle", "", "Bundle .tar.gz path (for --verify; also accepted as positional arg)")
	pubkeyPath := fs.String("pubkey", "", "Path to Ed25519 public key for DSSE verification")
	slsaPubkeyPath := fs.String("slsa-pubkey", "", "Optional separate Ed25519 public key for SLSA provenance (defaults to --pubkey)")
	workspaceRoot := fs.String("root", "", "Optional workspace root directory for os.OpenRoot confinement")
	allowUnsigned := fs.Bool("allow-unsigned-local", false, "Allow unsigned local attestations (dry-run only; default fail-closed)")

	boolFlags := map[string]bool{
		"cra":                  true,
		"verify":               true,
		"allow-unsigned-local": true,
	}
	if err := fs.Parse(reorderFlagsBeforePositional(args, boolFlags)); err != nil {
		return 1
	}

	if *doCRA && *doVerify {
		fmt.Fprintln(os.Stderr, "Error: --cra and --verify are mutually exclusive")
		return 1
	}
	if !*doCRA && !*doVerify {
		fmt.Fprintln(os.Stderr, "Error: specify --cra to assemble a bundle or --verify to verify one")
		printBundleUsage()
		return 1
	}

	var vexPub ed25519.PublicKey
	if strings.TrimSpace(*pubkeyPath) != "" {
		var err error
		vexPub, err = vex.ParseEd25519PublicKey(*pubkeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading --pubkey: %v\n", err)
			return 1
		}
	}

	var slsaPub ed25519.PublicKey
	if strings.TrimSpace(*slsaPubkeyPath) != "" {
		var err error
		slsaPub, err = vex.ParseEd25519PublicKey(*slsaPubkeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading --slsa-pubkey: %v\n", err)
			return 1
		}
	}

	if *doVerify {
		target := *bundlePath
		if target == "" && fs.NArg() > 0 {
			target = fs.Arg(0)
		}
		if target == "" {
			fmt.Fprintln(os.Stderr, "Error: --verify requires a bundle path (e.g., `bomhound bundle --verify dist/app-cra.tar.gz --pubkey pub.pem`)")
			return 1
		}

		res, err := cra.VerifyCRABundleWithOptions(target, cra.VerifyOptions{
			VEXPublicKey:       vexPub,
			SLSAPublicKey:      slsaPub,
			ExpectedBinaryPath: *binaryPath,
			AllowUnsignedLocal: *allowUnsigned,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "CRA bundle verification failed: %v\n", err)
			if errors.Is(err, cra.ErrDigestMismatch) {
				return cra.ExitCodeDigestMismatch
			}
			return 1
		}
		fmt.Fprintf(os.Stderr, "Verified EU CRA bundle (%s): subject=%s sha256=%s artifacts=%d\n",
			res.Manifest.SchemaVersion, res.Manifest.SubjectName, res.Manifest.SubjectSHA256, res.ArtifactCount)
		return 0
	}

	// --cra assemble mode
	manifest, err := cra.BuildCRABundle(cra.CRABundleSpec{
		StandardVersion:    cra.DefaultStandardVersion,
		WorkspaceRoot:      *workspaceRoot,
		BinaryPath:         *binaryPath,
		SBOMPath:           *sbomPath,
		VEXDSSEPath:        *vexPath,
		SLSAIntotoPath:     *provenancePath,
		RiskConfigPath:     *riskPath,
		AIBOMPath:          *aiBomPath,
		OutputTarGz:        *outPath,
		VEXPublicKey:       vexPub,
		SLSAPublicKey:      slsaPub,
		AllowUnsignedLocal: *allowUnsigned,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRA bundle creation failed: %v\n", err)
		if errors.Is(err, cra.ErrDigestMismatch) {
			return cra.ExitCodeDigestMismatch
		}
		return 1
	}

	fmt.Fprintf(os.Stderr, "Assembled EU CRA evidence bundle %s (subject=%s sha256=%s artifacts=%d)\n",
		*outPath, manifest.SubjectName, manifest.SubjectSHA256, len(manifest.Artifacts))
	return 0
}

func printBundleUsage() {
	fmt.Println(`bomhound bundle — Offline EU CRA (BS EN 40000-1-1 / 1-2) Lifecycle Evidence Bundler

Usage:
  bomhound bundle --cra --binary <bin> --sbom <sbom.cdx.json> --vex <vex.dsse.json> \
    --provenance <bin.intoto.jsonl> --pubkey <pub.pem> --out <cra-evidence.tar.gz>
  bomhound bundle --verify <cra-evidence.tar.gz> --pubkey <pub.pem>

Flags:
  --cra                  Assemble a deterministic offline CRA evidence bundle
  --verify               Verify an existing CRA evidence bundle (.tar.gz)
  --binary               Path to release binary (required for --cra; optional cross-check for --verify)
  --sbom                 Path to CycloneDX SBOM JSON
  --vex                  Path to DSSE-signed OpenVEX file
  --provenance           Path to Soulcaster SLSA v1.0 .intoto.jsonl file
  --risk                 Optional path to cra-risk.yaml lifecycle risk assessment metadata
  --ai-bom               Optional path to .ai-bom.yaml metadata
  --pubkey               Path to Ed25519 public key for DSSE verification
  --slsa-pubkey          Optional separate Ed25519 public key for SLSA provenance (defaults to --pubkey)
  --root                 Optional workspace root for os.OpenRoot path confinement
  --out                  Output deterministic .tar.gz path
  --allow-unsigned-local Allow unsigned local attestations (dry-run only; default fail-closed)

Exit Codes:
  0   Bundle assembled or verified cleanly
  1   General validation, signature, secret-scrub, or archive error
  10  Fail-closed SHA-256 subject-digest mismatch (mix-and-match tampering blocked)`)
}
