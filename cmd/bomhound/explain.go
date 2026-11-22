package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/bonjoski/bomhound/pkg/ux"
)

func runExplain(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	showWhy := false
	topic := "attribution"

	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--why":
			showWhy = true
		case "-h", "--help", "help":
			_, _ = fmt.Fprintln(stdout, "Usage: bomhound explain [attribution|cyclonedx|apache-4c|dmca-1202|sbom] [--why] [--json]")
			return 0
		default:
			if !strings.HasPrefix(a, "-") {
				topic = strings.ToLower(strings.TrimSpace(a))
			}
		}
	}

	switch topic {
	case "", "copyright", "license", "bomhound_compliance_gate_failed":
		topic = "attribution"
	case "apache", "apache2", "4c":
		topic = "apache-4c"
	case "dmca", "1202":
		topic = "dmca-1202"
	case "cdx":
		topic = "cyclonedx"
	}

	explanations := map[string]*ux.FixForwardError{
		"attribution": {
			Tool:           "bomhound",
			Code:           "BOMHOUND_EXPLAIN_ATTRIBUTION",
			Summary:        "Multi-author upstream copyright and license attribution enrichment for SBOMs",
			RemediationCmd: "bomhound --in-place sbom.cdx.json",
			WhyOneLiner:    "Extracts unabridged copyright notices from upstream repositories to satisfy Apache-2.0 §4c and 17 U.S.C. §1202.",
			DeepWhy:        "Standard SBOM generators record package names and SPDX identifiers but omit author copyright statements. Bomhound resolves Go vanity imports, npm packages, and GitHub repositories locally (with SSRF protection and Locksmith token isolation) and writes complete multi-author notices into CycloneDX Evidence.Copyright.",
			References:     []string{"https://www.apache.org/licenses/LICENSE-2.0#redistribution", "https://www.law.cornell.edu/uscode/text/17/1202"},
			ExitCode:       0,
		},
		"cyclonedx": {
			Tool:           "bomhound",
			Code:           "BOMHOUND_EXPLAIN_CYCLONEDX",
			Summary:        "Spec-compliant CycloneDX Evidence.Copyright enrichment preserving existing SBOM metadata",
			RemediationCmd: "cat sbom.cdx.json | bomhound - > enriched.cdx.json",
			WhyOneLiner:    "Streams CycloneDX JSON/XML via cyclonedx-go without dropping dependencies, hashes, or custom properties.",
			DeepWhy:        "Bomhound uses official cyclonedx-go decoders/encoders to populate each component's `evidence.copyright` array (and declared `copyright` when absent) while preserving serialNumber, metadata, dependencies, and externalReferences. Stdout stays pure SBOM JSON for UNIX pipes while diagnostics go strictly to stderr.",
			References:     []string{"https://cyclonedx.org/specification/overview/"},
			ExitCode:       0,
		},
		"apache-4c": {
			Tool:           "bomhound",
			Code:           "BOMHOUND_EXPLAIN_APACHE_4C",
			Summary:        "Apache License 2.0 Section 4(c) redistribution notice retention requirement",
			RemediationCmd: "bomhound --config .bomhound.yaml sbom.cdx.json",
			WhyOneLiner:    "Apache-2.0 §4c requires retaining all copyright, patent, trademark, and attribution notices when redistributing software.",
			DeepWhy:        "Under Apache License 2.0 Section 4(c), redistributing source or compiled derivative works requires keeping all upstream copyright and NOTICE attributions intact. Bomhound automates extracting those notices into your CycloneDX SBOM so release bundles and NOTICE files stay compliant without manual archaeology.",
			References:     []string{"https://www.apache.org/licenses/LICENSE-2.0#redistribution"},
			ExitCode:       0,
		},
		"dmca-1202": {
			Tool:           "bomhound",
			Code:           "BOMHOUND_EXPLAIN_DMCA_1202",
			Summary:        "17 U.S.C. §1202 Copyright Management Information (CMI) preservation",
			RemediationCmd: "bomhound --in-place sbom.cdx.json",
			WhyOneLiner:    "U.S. copyright law (17 U.S.C. §1202) prohibits intentionally removing or altering author copyright notices.",
			DeepWhy:        "17 U.S.C. §1202 protects Copyright Management Information (author names, copyright notices, license terms) from removal during redistribution or AI-assisted code bundling. Preserving complete multi-author copyright blocks in CycloneDX Evidence.Copyright provides an auditable attribution trail.",
			References:     []string{"https://www.law.cornell.edu/uscode/text/17/1202"},
			ExitCode:       0,
		},
		"sbom": {
			Tool:           "bomhound",
			Code:           "BOMHOUND_EXPLAIN_SBOM",
			Summary:        "Local CycloneDX SBOM receipts paired with Soulcaster SLSA provenance for Stage 4 CI",
			RemediationCmd: "bomhound --output-dir receipts sbom.cdx.json",
			WhyOneLiner:    "Produces a portable CycloneDX JSON receipt verifiable in GitHub Actions with zero SaaS control plane.",
			DeepWhy:        "Combining a Bomhound-enriched CycloneDX SBOM (`receipts/sbom.cdx.json`) with a Soulcaster SLSA v1.0 provenance receipt (`receipts/provenance.intoto.jsonl`) gives you automated PR verification via standard open-source GitHub Actions (`verify-local-receipts.yml`) while keeping 100% of execution on your local workstation.",
			References:     []string{"https://cyclonedx.org/", "docs/use-cases/01-sbom-license-enrichment.md"},
			ExitCode:       0,
		},
	}

	entry, ok := explanations[topic]
	if !ok {
		ffe := &ux.FixForwardError{
			Tool:           "bomhound",
			Code:           "BOMHOUND_EXPLAIN_UNKNOWN_TOPIC",
			Summary:        fmt.Sprintf("Unknown explain topic %q", topic),
			RemediationCmd: "bomhound explain attribution --why",
			WhyOneLiner:    "Available topics: attribution, cyclonedx, apache-4c, dmca-1202, sbom.",
			DeepWhy:        "Run `bomhound explain <topic> --why` with one of: attribution, cyclonedx, apache-4c, dmca-1202, sbom.",
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, asJSON, showWhy)
		return 1
	}

	if err := entry.Render(stdout, asJSON, showWhy); err != nil {
		return 1
	}
	return 0
}
