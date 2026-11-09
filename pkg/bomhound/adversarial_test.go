package bomhound

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestAdversarial_BMH04_LicenseFalsePositiveSubstringGuard ensures corporate names or
// prose containing substrings like "mit", "isc", or "mpl" NEVER false-match permissive
// SPDX licenses ("MIT", "ISC", "MPL-2.0").
func TestAdversarial_BMH04_LicenseFalsePositiveSubstringGuard(t *testing.T) {
	falsePositives := []string{
		"Proprietary - Acme Limited",
		"All Rights Reserved - Committer Corp",
		"Commercial - Cisco Systems Inc.",
		"Proprietary Example Software License",
		"GPL-3.0-only",
		"AGPL-3.0-or-later",
	}

	for _, raw := range falsePositives {
		got := inferLicenseFromText(raw)
		if got == "MIT" || got == "ISC" || got == "MPL-2.0" {
			t.Fatalf("BMH-04 CRITICAL: %q falsely normalized to permissive license %q!", raw, got)
		}
	}

	// Legitimate permissive license strings must still normalize cleanly
	truePositives := map[string]string{
		"MIT":                        "MIT",
		"The MIT License":            "MIT",
		"MIT AND Apache-2.0":         "Apache-2.0",
		"Apache-2.0":                 "Apache-2.0",
		"Apache License 2.0":         "Apache-2.0",
		"BSD-3-Clause":               "BSD-3-Clause",
		"BSD-2-Clause":               "BSD-2-Clause",
		"ISC":                        "ISC",
		"ISC License":                "ISC",
		"MPL-2.0":                    "MPL-2.0",
		"Mozilla Public License 2.0": "MPL-2.0",
	}
	for raw, want := range truePositives {
		if got := inferLicenseFromText(raw); got != want {
			t.Errorf("inferLicenseFromText(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestAdversarial_BMH04_UntrustedCWDCacheIgnored verifies that a poisoned .sbom-cache.json
// planted in an untrusted repository working directory is NOT auto-loaded by LookupLicenses.
func TestAdversarial_BMH04_UntrustedCWDCacheIgnored(t *testing.T) {
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(origWd)

	tmpDir := t.TempDir()
	t.Setenv("HOME", filepath.Join(tmpDir, "cleanhome"))

	poisonedJSON := `{
  "copyrights": {
    "pkg:generic/poisoned-agpl-pkg@1.0.0": "MIT License"
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, ".sbom-cache.json"), []byte(poisonedJSON), 0600); err != nil {
		t.Fatalf("write poisoned cache: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// Reset singleton so GetDefaultCache runs fresh in the poisoned CWD
	resetDefaultCacheForTest()
	defer resetDefaultCacheForTest()

	res, err := LookupLicenses(context.Background(), []string{"pkg:generic/poisoned-agpl-pkg@1.0.0"})
	if err != nil {
		t.Fatalf("LookupLicenses failed: %v", err)
	}
	if got := res["pkg:generic/poisoned-agpl-pkg@1.0.0"]; got != "UNKNOWN" {
		t.Fatalf("BMH-04 regression: poisoned CWD .sbom-cache.json forged license %q!", got)
	}
}
