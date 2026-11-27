# EU Cyber Resilience Act (`BS EN 40000-1-1` / `1-2`) Offline Lifecycle Evidence Bundle

> **Standards:** `BS EN 40000-1-1:2026` (Vocabulary) · `BS EN 40000-1-2:2026` (Product Cybersecurity Risk Management & Lifecycle Evidence) · CycloneDX 1.6 (with AI-BOM) · OpenVEX v0.2.0 · in-toto v1.0 / DSSE v1.0 · SLSA v1.0  
> **Deferred Clauses:** `BS EN 40000-1-3` (vulnerability handling schema fields deferred pending BSI 2027 publication)  
> **Visibility:** 100% Offline, Single-Repo Open-Source CLI (`PUBLIC_OSS`) — zero cloud or SaaS dependencies

---

## Problem

Ahead of mandatory EU Cyber Resilience Act (CRA) CE marking on **December 11, 2027**, commercial and open-source software releases must provide verifiable, tamper-evident lifecycle evidence tying together:

1. **Software & AI Bill of Materials:** Legally attributed CycloneDX 1.6 SBOM including optional local AI models and MCP servers (`.ai-bom.yaml`).
2. **Signed Vulnerability Exploitability eXchange (VEX):** OpenVEX v0.2.0 statements wrapped in a DSSE v1 / in-toto v1.0 envelope cryptographically bound to the exact release binary SHA-256 digest.
3. **Hermetic Build Provenance:** Soulcaster SLSA v1.0 `.intoto.jsonl` provenance attesting the exact same binary SHA-256 digest.
4. **Lifecycle Risk Assessment Metadata:** Optional `cra-risk.yaml` documenting product threat modeling and support lifecycle under `BS EN 40000-1-2`.

Without cryptographic subject-digest cross-verification, an attacker or broken pipeline can perform a **mix-and-match attack**—pairing an old clean VEX or old SLSA provenance file with a modified release binary.

---

## End-to-End Developer Workflow

### 1. Optional `.ai-bom.yaml` (CycloneDX 1.6 AI-BOM Metadata)

Create a repo-local `.ai-bom.yaml` (strictly read via Go's `os.OpenRoot`, refusing symlinks and `..` traversal):

```yaml
version: "1"
components:
  - name: "qwen3-coder-local"
    type: "machine-learning-model"
    version: "32b-q4"
    provider: "local-ollama"
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    airgap_capable: true
    license: "Apache-2.0"
  - name: "coppermind-mcp"
    type: "mcp-server"
    version: "0.9.0"
    provider: "bonjoski"
    airgap_capable: true
```

### 2. Optional `cra-risk.yaml` (`BS EN 40000-1-2` Risk Metadata)

```yaml
standard: "BS EN 40000-1-2:2026"
product: "myapp"
support_period_months: 60
security_contact: "security@example.org"
threat_model: "STRIDE reviewed; offline single-binary CLI with fail-closed verification"
```

### 3. Hermetic Build + Enrich + DSSE VEX + Offline CRA Bundle

```bash
# 1. Hermetic build + DSSE-signed SLSA v1.0 provenance (Soulcaster)
soulcaster wrap -o bin/myapp --sign-key release.key -- go build -trimpath -o bin/myapp ./cmd/myapp

# 2. Enrich CycloneDX SBOM with copyrights + CycloneDX 1.6 AI-BOM components
#    (Add --offline to inject AI-BOM metadata without GitHub API lookups)
bomhound enrich \
  --input sbom.cdx.json \
  --ai-bom .ai-bom.yaml \
  --output sbom-enriched.cdx.json

# 3. Emit DSSE-signed OpenVEX v0.2.0 bound to exact SHA-256 of bin/myapp
#    (Supports --key <ed25519.pem>, LOCKSMITH_SOCKET, or ephemeral offline keypair with --pubkey-out)
bomhound vex \
  --binary bin/myapp \
  --sign \
  --key release.key \
  --pubkey-out release.pub \
  --output bin/myapp.vex.dsse.json

# 4. Assemble deterministic, tamper-evident offline CRA evidence bundle
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
bomhound bundle --cra \
  --binary bin/myapp \
  --sbom sbom-enriched.cdx.json \
  --vex bin/myapp.vex.dsse.json \
  --provenance bin/myapp.intoto.jsonl \
  --risk cra-risk.yaml \
  --ai-bom .ai-bom.yaml \
  --pubkey release.pub \
  --out dist/myapp-v1.0.0-cra-evidence.tar.gz

# 5. Air-gapped offline verification
bomhound bundle --verify dist/myapp-v1.0.0-cra-evidence.tar.gz \
  --pubkey release.pub \
  --binary bin/myapp
```

---

## Security & Fail-Closed Guarantees

| Threat | Fail-Closed Control |
| :--- | :--- |
| **Mix-and-Match Digest Tampering** | Cross-verifies `sha256(binary) == vex.subject[0].digest.sha256 == slsa.subject[*].digest.sha256`. Aborts immediately with **Exit Code 10** on mismatch. |
| **Forged / Unsigned Attestations** | Requires valid Ed25519 DSSE v1 signature verification on both OpenVEX and SLSA provenance (unsigned artifacts fail closed unless `--allow-unsigned-local` is explicitly passed for local dry-runs). |
| **Secret / Credential Leakage** | Built-in secret scrubber scans SBOM, VEX, SLSA, `cra-risk.yaml`, and `.ai-bom.yaml` for AWS/GitHub/Anthropic/OpenAI/PEM/high-entropy credentials and aborts without echoing secret values. |
| **Host Path Disclosure** | Strips absolute host paths (`filepath.Base`) in `manifest.json` and produces a flat archive layout (`manifest.json`, `sbom.cdx.json`, `vex.dsse.json`, `provenance.intoto.jsonl`, optional `cra-risk.yaml`, optional `ai-bom.yaml`). |
| **Symlink & Traversal Escapes** | Confines `.ai-bom.yaml` and workspace inputs via `os.OpenRoot`, rejects symlinks on inputs/outputs, and writes `.tar.gz` atomically via temp file + `Sync` + `os.Rename`. |
| **Tar-Slip & Archive Bombs** | `bomhound bundle --verify` enforces strict `io.LimitReader` caps (**32 MiB/entry**, **128 MiB total**), rejects symlinks/hardlinks/absolute/`..`/nested paths, and validates every entry against `manifest.json` SHA-256 digests. |
| **Reproducibility** | Lexicographically sorted tar entries, zeroed UID/GID, USTAR headers, and pinned `SOURCE_DATE_EPOCH` timestamps produce byte-identical `.tar.gz` archives across runners. |

---

## Bundle Layout (`manifest.json`)

```json
{
  "schema_version": "cra-evidence-v1",
  "standards": [
    "BS EN 40000-1-1:2026",
    "BS EN 40000-1-2:2026"
  ],
  "subject_name": "myapp",
  "subject_sha256": "<64-char-hex-sha256>",
  "artifacts": {
    "ai-bom.yaml": "<sha256>",
    "cra-risk.yaml": "<sha256>",
    "provenance.intoto.jsonl": "<sha256>",
    "sbom.cdx.json": "<sha256>",
    "vex.dsse.json": "<sha256>"
  },
  "deferred_clauses": [
    "BS EN 40000-1-3 (pending BSI 2027)"
  ],
  "generated_at": "2026-11-27T00:00:00Z"
}
```
