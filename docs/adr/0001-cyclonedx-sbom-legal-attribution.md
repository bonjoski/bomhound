# ADR-0001: CycloneDX SBOM Legal Attribution & Copyright Notice Extraction

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/sbom`, `cmd/bomhound`
- **Deciders:** Lead Supply Chain Architect & Open Source Licensing Engineer

---

## 1. Context & Problem Statement

Modern software releases bundle hundreds of transitive open-source dependencies.
- Open-source licenses (Apache 2.0 §4c, BSD, MIT) legally require redistributing verbatim copyright notices and original license texts alongside binaries.
- Standard SBOM generators list package names and license IDs (e.g. `Apache-2.0`), but fail to extract the actual verbatim copyright statements and `NOTICE` file blocks, leaving organizations legally non-compliant.

---

## 2. Decision Outcome

We built **Bomhound**, a specialized license attribution and SBOM enrichment tool:

1. **Verbatim Notice & Copyright Extraction:**
   - Deep-scans source tarballs and go.mod / npm lockfiles to extract exact legal copyright headers and `NOTICE` contents.
2. **CycloneDX Enrichment:**
   - Enriches standard CycloneDX SBOMs with embedded legal text in `components[].licenses[].license.text`.
3. **Automated `NOTICE` Generator:**
   - Produces reproducible, alphabetically sorted `NOTICE` files for inclusion in binary release archives.

---

## 3. Consequences

- **Positive:** Automates legal copyright compliance; prevents open-source attribution lawsuits.
- **Negative:** Deep source scanning adds ~5s to release preparation pipelines.
