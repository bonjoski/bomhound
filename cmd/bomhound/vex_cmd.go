package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/bomhound/pkg/cra"
	"github.com/bonjoski/bomhound/pkg/vex"
)

func runVEX(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printVEXUsage()
		return 0
	}

	subcmd := args[0]
	switch subcmd {
	case "kernel":
		return runVEXKernel(args[1:])
	default:
		if strings.HasPrefix(subcmd, "-") {
			return runVEXDirect(args)
		}
		fmt.Fprintf(os.Stderr, "Unknown vex subcommand: %s\n", subcmd)
		printVEXUsage()
		return 1
	}
}

func printVEXUsage() {
	fmt.Println(`bomhound vex — OpenVEX Statement Generator & DSSE Attestation Signer/Verifier

Usage:
  bomhound vex --binary <path> --sign [flags]
  bomhound vex --verify --binary <path> --pubkey <pub.pem> <vex.dsse.json>
  bomhound vex kernel [flags]

Sign / Verify Flags:
  --sign              Wrap OpenVEX v0.2.0 in an in-toto v1.0 DSSE envelope bound to --binary
  --verify            Verify a DSSE-signed OpenVEX file against --pubkey and --binary
  --binary            Path to release binary whose SHA-256 binds in-toto subject[0]
  --input             Input OpenVEX JSON (for --sign) or DSSE OpenVEX JSON (for --verify)
  --output            Path to write OpenVEX or DSSE JSON (default: stdout)
  --key               Path to Ed25519 private key (for --sign) or public key fallback (for --verify)
  --pubkey            Path to Ed25519 public key (for --verify)
  --pubkey-out        Path to write signing Ed25519 public key PEM
  --locksmith-socket  Optional LOCKSMITH_SOCKET path for Ed25519 DSSE signing
  --product           Product PURL or name (default: pkg:generic/<binary-basename>)
  --author            OpenVEX author string

Kernel Reachability Subcommand (bomhound vex kernel):
  --kconfig           Path to Linux kernel .config file
  --elf               Path to uncompressed vmlinux ELF binary (optional)
  --kallsyms          Path to /proc/kallsyms or symbol dump (optional)
  --product           Product package URL or name
  --output            Path to output OpenVEX JSON file (default: stdout)
  --sign              Optionally wrap & sign the kernel OpenVEX in DSSE (requires --binary)
  --binary            Release artifact path for DSSE subject binding
  --key               Optional Ed25519 private key path
  --pubkey-out        Optional Ed25519 public key PEM output path`)
}

func runVEXDirect(args []string) int {
	fs := flag.NewFlagSet("bomhound vex", flag.ContinueOnError)
	doSign := fs.Bool("sign", false, "Sign OpenVEX v0.2.0 in a DSSE v1 / in-toto v1.0 envelope bound to --binary")
	doVerify := fs.Bool("verify", false, "Verify a DSSE-signed OpenVEX envelope against --pubkey and --binary")
	binaryPath := fs.String("binary", "", "Path to release binary whose SHA-256 binds in-toto subject")
	inputPath := fs.String("input", "", "Input OpenVEX JSON (for --sign) or DSSE VEX file (for --verify)")
	outputPath := fs.String("output", "", "Path to output JSON file (default: stdout)")
	keyPath := fs.String("key", "", "Path to Ed25519 private key (for --sign) or public key (for --verify)")
	pubkeyPath := fs.String("pubkey", "", "Path to Ed25519 public key (for --verify)")
	pubkeyOutPath := fs.String("pubkey-out", "", "Path to write Ed25519 public key PEM after signing")
	locksmithSocket := fs.String("locksmith-socket", "", "Optional LOCKSMITH_SOCKET path for DSSE signing")
	product := fs.String("product", "", "Product package URL or name")
	author := fs.String("author", "bomhound-vex / sovereign-agent-security", "OpenVEX document author")

	if err := fs.Parse(reorderFlagsBeforePositional(args, map[string]bool{
		"sign": true, "verify": true,
	})); err != nil {
		return 1
	}

	if *doSign && *doVerify {
		fmt.Fprintln(os.Stderr, "Error: --sign and --verify are mutually exclusive")
		return 1
	}
	if !*doSign && !*doVerify {
		fmt.Fprintln(os.Stderr, "Error: specify --sign, --verify, or subcommand `kernel`")
		return 1
	}

	if *doVerify {
		target := *inputPath
		if target == "" && fs.NArg() > 0 {
			target = fs.Arg(0)
		}
		if target == "" {
			fmt.Fprintln(os.Stderr, "Error: --verify requires --input <vex.dsse.json> or a positional file path")
			return 1
		}
		if *binaryPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --verify requires --binary <path> for SHA-256 subject binding verification")
			return 1
		}
		pkInput := *pubkeyPath
		if pkInput == "" {
			pkInput = *keyPath
		}
		if pkInput == "" {
			fmt.Fprintln(os.Stderr, "Error: --verify requires --pubkey <path> (or --key <pub.pem>)")
			return 1
		}

		pubKey, err := vex.ParseEd25519PublicKey(pkInput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading Ed25519 public key: %v\n", err)
			return 1
		}
		expectedSHA, err := vex.HashFileSHA256(*binaryPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error hashing binary: %v\n", err)
			return 1
		}
		dsseBytes, err := readRegularFileBounded(target, 32<<20)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading DSSE VEX file: %v\n", err)
			return 1
		}

		stmt, err := vex.VerifySignedOpenVEX(dsseBytes, pubKey, expectedSHA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "OpenVEX verification failed: %v\n", err)
			if errors.Is(err, vex.ErrSubjectDigestMismatch) {
				return cra.ExitCodeDigestMismatch
			}
			return 1
		}
		fmt.Fprintf(os.Stderr, "Verified DSSE OpenVEX: subject=%s sha256=%s statements=%d\n",
			stmt.Subject[0].Name, stmt.Subject[0].Digest["sha256"], len(stmt.Predicate.Statements))
		return 0
	}

	// --sign mode
	if *binaryPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --sign requires --binary <path> to bind in-toto subject SHA-256")
		return 1
	}

	var doc *vex.OpenVEXDocument
	if *inputPath != "" {
		raw, err := readRegularFileBounded(*inputPath, 32<<20)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input OpenVEX file: %v\n", err)
			return 1
		}
		var parsed vex.OpenVEXDocument
		if err := json.Unmarshal(raw, &parsed); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing input OpenVEX JSON: %v\n", err)
			return 1
		}
		if parsed.Context == "" {
			parsed.Context = vex.OpenVEXContext
		}
		doc = &parsed
	} else {
		doc = vex.NewOpenVEXDocument(*author)
		prod := *product
		if prod == "" {
			prod = "pkg:generic/" + filepath.Base(filepath.Clean(*binaryPath))
		}
		doc.Statements = append(doc.Statements, vex.Statement{
			Vulnerability: vex.VulnerabilityIdent{
				Name:        "NONE",
				Description: "Baseline release OpenVEX attestation bound to artifact digest",
			},
			Products:      []string{prod},
			Status:        vex.StatusNotAffected,
			Justification: vex.JustificationVulnerableCodeNotPresent,
			StatusNotes:   "No known exploitable vulnerabilities declared for this release artifact.",
		})
	}

	sock := *locksmithSocket
	if sock == "" && *keyPath == "" {
		sock = os.Getenv("LOCKSMITH_SOCKET")
	}

	dsseBytes, pubKey, err := vex.SignOpenVEXWithKey(doc, vex.SignedVEXOptions{
		ArtifactPath:    *binaryPath,
		OfflineKeyPath:  *keyPath,
		LocksmithSocket: sock,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing OpenVEX document: %v\n", err)
		return 1
	}

	if *pubkeyOutPath != "" && len(pubKey) == ed25519.PublicKeySize {
		pemBytes, err := vex.EncodeEd25519PublicKeyPEM(pubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding Ed25519 public key: %v\n", err)
			return 1
		}
		if err := writeFileAtomicNoSymlink(*pubkeyOutPath, pemBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing public key file: %v\n", err)
			return 1
		}
	}

	if *outputPath != "" {
		if err := writeFileAtomicNoSymlink(*outputPath, dsseBytes, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "DSSE-signed OpenVEX document written to %s (%d statements)\n", filepath.Clean(*outputPath), len(doc.Statements))
	} else {
		fmt.Print(string(dsseBytes))
	}

	return 0
}

func runVEXKernel(args []string) int {
	fs := flag.NewFlagSet("bomhound vex kernel", flag.ContinueOnError)
	kconfigPath := fs.String("kconfig", "", "Path to Linux kernel .config file")
	elfPath := fs.String("elf", "", "Path to uncompressed vmlinux ELF binary")
	kallsymsPath := fs.String("kallsyms", "", "Path to /proc/kallsyms or symbol dump")
	product := fs.String("product", "pkg:generic/linux-microvm-kernel@unknown", "Product package URL")
	outputPath := fs.String("output", "", "Path to write OpenVEX JSON (default: stdout)")
	doSign := fs.Bool("sign", false, "Sign generated OpenVEX inside a DSSE v1 envelope bound to --binary")
	binaryPath := fs.String("binary", "", "Binary path for DSSE subject binding (required with --sign)")
	keyPath := fs.String("key", "", "Path to Ed25519 private key for DSSE signing")
	pubkeyOutPath := fs.String("pubkey-out", "", "Path to write Ed25519 public key PEM")
	locksmithSocket := fs.String("locksmith-socket", "", "Optional LOCKSMITH_SOCKET path for DSSE signing")

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *kconfigPath == "" && *elfPath == "" && *kallsymsPath == "" {
		fmt.Fprintln(os.Stderr, "Error: at least one of --kconfig, --elf, or --kallsyms must be specified")
		return 1
	}

	var kconfig vex.KconfigMap
	if *kconfigPath != "" {
		var err error
		kconfig, err = vex.ParseKconfigFile(*kconfigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing Kconfig: %v\n", err)
			return 1
		}
	}

	symbols := make(map[string]bool)
	if *elfPath != "" {
		elfSyms, err := vex.ExtractELFSymbols(*elfPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed reading ELF symbols from %s: %v\n", *elfPath, err)
		} else {
			for k, v := range elfSyms {
				symbols[k] = v
			}
		}
	}

	if *kallsymsPath != "" {
		ksyms, err := vex.ParseKallsymsFile(*kallsymsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed reading kallsyms from %s: %v\n", *kallsymsPath, err)
		} else {
			for k, v := range ksyms {
				symbols[k] = v
			}
		}
	}

	doc, err := vex.AnalyzeKernelReachability(kconfig, symbols, nil, *product, "bomhound-vex / sovereign-agent-security")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing kernel reachability: %v\n", err)
		return 1
	}

	var data []byte
	if *doSign {
		if *binaryPath == "" {
			fmt.Fprintln(os.Stderr, "Error: --sign requires --binary <path>")
			return 1
		}
		sock := *locksmithSocket
		if sock == "" && *keyPath == "" {
			sock = os.Getenv("LOCKSMITH_SOCKET")
		}
		var pubKey ed25519.PublicKey
		data, pubKey, err = vex.SignOpenVEXWithKey(doc, vex.SignedVEXOptions{
			ArtifactPath:    *binaryPath,
			OfflineKeyPath:  *keyPath,
			LocksmithSocket: sock,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error signing OpenVEX document: %v\n", err)
			return 1
		}
		if *pubkeyOutPath != "" && len(pubKey) == ed25519.PublicKeySize {
			pemBytes, err := vex.EncodeEd25519PublicKeyPEM(pubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding public key PEM: %v\n", err)
				return 1
			}
			if err := writeFileAtomicNoSymlink(*pubkeyOutPath, pemBytes, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing public key PEM: %v\n", err)
				return 1
			}
		}
	} else {
		data, err = doc.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error serializing OpenVEX document: %v\n", err)
			return 1
		}
	}

	if *outputPath != "" {
		cleanOut := filepath.Clean(*outputPath)
		if err := writeFileAtomicNoSymlink(cleanOut, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "OpenVEX document successfully written to %s (%d statements)\n", cleanOut, len(doc.Statements))
	} else {
		fmt.Println(string(data))
	}

	return 0
}
