# bomhound

A high-performance CLI tool and Go library for enriching Software Bill of Materials (SBOMs) with copyright, upstream source provenance, and legal attribution notices.

[![CI](https://github.com/bonjoski/bomhound/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/bomhound/actions/workflows/ci.yml)
[![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev)
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
- **CycloneDX 1.6 AI-BOM Metadata (`--ai-bom`)**: Inject local AI models (`machine-learning-model`), MCP servers, and agent runtimes from a root-confined `.ai-bom.yaml` (`os.OpenRoot`) without mutating existing hashes or copyrights.
- **DSSE-Signed OpenVEX (`bomhound vex --sign`)**: Wrap OpenVEX v0.2.0 statements in standard in-toto v1.0 / DSSE v1 Ed25519 envelopes cryptographically bound to the release binary SHA-256 digest (via local Ed25519 key, ephemeral offline keypair, or optional `LOCKSMITH_SOCKET`).
- **Offline EU CRA Lifecycle Evidence Bundler (`bomhound bundle --cra`)**: Assemble and verify deterministic, air-gapped `BS EN 40000-1-1` / `1-2` `.tar.gz` bundles cross-verifying exact binary SHA-256 across OpenVEX and Soulcaster SLSA provenance (fail-closed Exit Code 10 on mix-and-match tampering, built-in secret scrubber, anti-tar-slip & bounded memory verification).

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

---

## 💡 Core Use Cases & Recipes

Every primary developer use case is backed by dedicated, copy-pasteable recipes in [**`docs/use-cases/`**](docs/use-cases/README.md):

| Use Case | Scenario & Quick Recipe | Full Guide |
| :--- | :--- | :--- |
| **CycloneDX Legal License Enrichment** | Enrich bare SBOMs with complete license texts and author copyrights:<br/>`bomhound --input bom.json --output enriched-bom.json` | [Guide](docs/use-cases/01-sbom-license-enrichment.md) |
| **Vanity Import URL Resolution** | Map vanity paths (`go.uber.org/zap`) to upstream Git repositories:<br/>`bomhound --config .bomhound.yaml bom.json` | [Guide](docs/use-cases/02-vanity-url-resolution.md) |
| **GitHub Actions In-Place Release Pipeline** | Enrich SBOMs in-place within CI release workflows:<br/>`bomhound --in-place bom.json` | [Guide](docs/use-cases/03-github-actions-release-pipeline.md) |
| **Progressive Legal Attribution Disclosure (`--why`)** | Explain Apache-2.0 §4c, 17 U.S.C. §1202, and CycloneDX `Evidence.Copyright` requirements:<br/>`bomhound explain attribution --why` | [Recipe](#progressive-disclosure---why--calm-summaries) |
| **EU CRA Lifecycle Evidence Bundle (`BS EN 40000-1-2`)** | Enrich CycloneDX 1.6 AI-BOM, sign DSSE OpenVEX, and assemble/verify deterministic offline CRA bundles:<br/>`bomhound bundle --cra ... && bomhound bundle --verify ...` | [Guide](docs/use-cases/eu-cra-lifecycle-evidence-bundle.md) |

### Progressive Disclosure (`--why`) & Calm Summaries

`bomhound` emits a calm ≤3-line copyright coverage summary on `stderr` (keeping `stdout` pure CycloneDX JSON for UNIX pipes) and supports UB-CLI-v2 progressive disclosure via `bomhound explain`:

```bash
# Default calm attribution explanation (<= 3 lines)
bomhound explain attribution

# Expand Apache-2.0 §4c & 17 U.S.C. §1202 rationale (--why) or machine-readable JSON (--json)
bomhound explain apache-4c --why
bomhound explain dmca-1202 --why
bomhound explain cyclonedx --json
```

Available `bomhound explain` topics: `attribution`, `cyclonedx`, `apache-4c`, `dmca-1202`, `sbom`.

---

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

## Verifying Releases & SLSA Provenance

All official releases generate cryptographic SLSA v1.0 build provenance.

Verify a downloaded release archive:
```bash
gh attestation verify dist/bomhound_Linux_x86_64.tar.gz --repo bonjoski/bomhound
```

Or verify offline using Soulcaster:
```bash
soulcaster verify --attestation bomhound.intoto.jsonl bin/bomhound
```

---

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) for details.
