# Bomhound Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, SBOM extraction models, and open-source license attribution invariants governing [`bonjoski/bomhound`](https://github.com/bonjoski/bomhound).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-cyclonedx-sbom-legal-attribution.md)** | **CycloneDX SBOM Legal Attribution & Copyright Notice Extraction** | `Accepted` | 2026-10-30 | `pkg/sbom`, `cmd/bomhound` |

---

## Architectural Principles

1. **Strict Legal Compliance:** Automates Apache 2.0 §4c and MIT copyright notice attribution extraction directly from upstream source packages.
2. **Standardized CycloneDX JSON:** Ingests and generates standard CycloneDX v1.5+ SBOMs with full component hashes and license expressions.
3. **Deterministic Notice File Generation:** Builds deterministic, audit-ready `NOTICE` and `THIRD_PARTY_LICENSES` files with zero runtime cloud dependency.
