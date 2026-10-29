# bomhound

A high-performance CLI tool and Go library for enriching Software Bill of Materials (SBOMs) with copyright, upstream source provenance, and legal attribution notices.

[![CI](https://github.com/bonjoski/bomhound/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/bomhound/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/bonjoski/bomhound)](https://goreportcard.com/report/github.com/bonjoski/bomhound)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## Features

- **Multi-Author Copyright Extraction**: Extracts full, unabridged multi-line copyright blocks and multiple distinct author statements complying with Apache-2.0 §4c and 17 U.S.C. § 1202.
- **CycloneDX Spec Compliant**: Emits standard CycloneDX `Evidence.Copyright` schema using official `cyclonedx-go` streaming decoders/encoders, preserving all existing properties, dependencies, and metadata.
- **Go Vanity URL & Registry Resolution**: Resolves custom Go vanity domains (`golang.org/x/*`, `k8s.io/*`, `gopkg.in/*`, etc.) and NPM packages to upstream source repositories.
- **SSRF & Network Hardening**: Built-in socket-level firewall blocks private IP ranges (RFC 1918), loopback, link-local, and cloud metadata endpoints (`169.254.169.254`). Enforces 3 redirect hops and prevents HTTPS-to-HTTP downgrade attacks.
- **UNIX Pipeline Ergonomics**: Seamlessly ingest SBOMs via `stdin` (`bomhound -`) and write enriched CycloneDX JSON to `os.Stdout`, keeping diagnostics cleanly separated on `os.Stderr`.
- **Policy Engine (`.bomhound.yaml`)**: Configurable exclusion rules with glob/prefix matching for internal, enterprise, or proprietary packages.
- **CI/CD Quality Gate**: Enforce coverage thresholds with `--min-coverage <percent>` and `--fail-on-missing` returning non-zero exit codes (Exit Code 5) on compliance failure.
- **High-Performance Caching**: Atomic read-merge-write caching with content-addressed directory stores and negative lookup caching with 7-day TTL.

---

## Installation

### Prerequisites
- Go 1.21 or later
- GitHub Personal Access Token (PAT) managed securely:
  - Configured via [Locksmith](https://github.com/bonjoski/locksmith) biometric vault (configured in `.bomhound.yaml` or `--locksmith-key`)
  - Piped via standard input (`--token-stdin`)
  - Retrieved automatically from `gh auth token` fallback
  *(Note: Environment variables such as `GITHUB_TOKEN` are intentionally **not** read to eliminate credential exposure in `/proc` tables, subshells, and CI environment dumps).*

### Homebrew (macOS & Linux)
```bash
brew tap bonjoski/tap
brew install bomhound
```

### Go Install
```bash
go install github.com/bonjoski/bomhound/cmd/bomhound@latest
```

### Build from Source
```bash
git clone https://github.com/bonjoski/bomhound.git
cd bomhound
make build
```

---

## Quick Start & Usage

### 1. In-place Mutation
Enrich an existing SBOM in place:
```bash
bomhound -i testdata/sample-sbom.cdx.json
```

### 2. UNIX Pipe Workflow
Stream an SBOM through `stdin` and write enriched output to `stdout`:
```bash
cat testdata/sample-sbom.cdx.json | bomhound - > enriched-sbom.cdx.json
```

### 3. CI Gate Mode
Enforce coverage thresholds and exit with code 5 on failure by configuring `compliance` in `.bomhound.yaml`:
```bash
bomhound --config .bomhound.yaml testdata/sample-sbom.cdx.json
```

### 4. Direct Token via Stdin
In automated CI/CD runners where Locksmith is not available:
```bash
echo "$SECRET_TOKEN" | bomhound --token-stdin testdata/sample-sbom.cdx.json
```

### 5. Batch Directory Processing
Process all SBOMs in a directory concurrently:
```bash
bomhound --concurrency 20 --output-dir ./enriched ./testdata/
```

---

## Command-Line Options

```
Usage:
  bomhound [flags] <file|dir|->

Flags:
  -c, --concurrency int          Number of concurrent workers (default 5)
  -o, --output-dir string        Directory to save enriched SBOMs (default "output")
  -i, --in-place                 Overwrite input SBOM files in-place
      --config string            Path to custom .bomhound.yaml configuration file
      --locksmith-key string     Key name for GitHub token in Locksmith vault (overrides config)
      --token-stdin              Read GitHub token from standard input
  -v, --version                  Print version information and exit
```

---

## Configuration (`.bomhound.yaml`)

`bomhound` looks for a `.bomhound.yaml` file in the current working directory, its parent directories, or in `~/.config/bomhound/config.yaml`.

> [!TIP]
> Copy the provided template to get started:
> ```bash
> cp .bomhound.example.yaml .bomhound.yaml
> ```
> `.bomhound.yaml` and `*.local.yaml` are ignored by git so your private vault key configurations remain local to your workstation.

```yaml
version: "1"

# Authentication settings (hardware-bound Locksmith vault)
auth:
  locksmith_key: "GH-Read" # Name of your secret in Locksmith ('locksmith add <key>')

# Exclusion rules for internal/private components or non-library artifacts
exclude:
  purls:
    - "pkg:rpm/*"
    - "pkg:golang/mycompany.internal/*"
  names:
    - "@mycompany/*"

# Custom vanity URL mappings (prefix -> target github repo)
vanity_urls:
  "software.sslmate.com/src/go-pkcs12": "SSLMate/go-pkcs12"

# Cache configuration
cache:
  dir: ".bomhound-cache"
  ttl_days: 30

# Compliance threshold enforcement (exits with code 5 if threshold is breached)
compliance:
  min_coverage_percent: 85.0
  fail_on_missing: false
```

---

## Using as a Go Library

`bomhound` exposes its core enrichment engine and embedded default caches for programmatic integration:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/bonjoski/bomhound/pkg/bomhound"
)

func main() {
	ctx := context.Background()
	enricher := bomhound.NewEnricher()

	// Direct lookup for a package URL
	entry, err := enricher.LookupPURL(ctx, "pkg:golang/github.com/google/uuid@v1.6.0")
	if err != nil {
		log.Fatalf("Lookup failed: %v", err)
	}

	for _, c := range entry.Copyrights {
		fmt.Printf("Copyright: %s\n", c)
	}
}
```

---

## Security & Hardening

- **Credential Isolation**: GitHub tokens are never read from environment variables to prevent accidental exposure in `/proc/<pid>/environ`, subshells, logs, or CI runner dumps. Authentication is strictly config-driven: tokens are retrieved on-demand from the hardware-backed [Locksmith](https://github.com/bonjoski/locksmith) CLI vault (`locksmith get <key> -n`), piped via `--token-stdin`, or resolved via `gh auth token`. No credentials or personal vault keys are ever persisted or committed to git.
- **SSRF Mitigation**: Custom HTTP dialer enforces RFC 1918, RFC 3927, and RFC 4291 network boundaries, protecting against server-side request forgery when fetching Go vanity meta tags.
- **Denial-of-Service Protection**: All external response bodies are bounded by `io.LimitReader` (2MB max) to eliminate memory exhaustion from malicious redirects or responses.
- **Atomic File Writing**: File writes use temporary files and atomic `os.Rename` with strict permission bits (`0600` / `0644`), preventing partial writes and symlink destination hijacking.

---

## Development

```bash
# Run unit and adversarial test suites
make test

# Run vulnerability scanner
make vulncheck

# Run linter
make lint

# Build binary
make build
```

---

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
