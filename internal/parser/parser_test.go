package parser

import (
	"os"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestGetPackageType(t *testing.T) {
	tests := []struct {
		purl     string
		expected string
	}{
		{"pkg:golang/github.com/foo/bar", "golang"},
		{"pkg:npm/@foo/bar@1.0.0", "npm"},
		{"pkg:maven/org.foo/bar@2.0.0", "maven"},
		{"pkg:pypi/requests@2.28.0", "pypi"},
		{"invalid", "unknown"},
		{"pkg:", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		if got := GetPackageType(tt.purl); got != tt.expected {
			t.Errorf("GetPackageType(%q) = %q, want %q", tt.purl, got, tt.expected)
		}
	}
}

func TestParseAndSaveSBOM(t *testing.T) {
	inputContent := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "name": "test-component",
      "purl": "pkg:npm/test-component@1.0.0",
      "type": "library"
    }
  ]
}`
	tmpInput, err := os.CreateTemp("", "sbom-input-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp input file: %v", err)
	}
	defer os.Remove(tmpInput.Name())

	if _, err := tmpInput.WriteString(inputContent); err != nil {
		t.Fatalf("Failed to write to temp input file: %v", err)
	}
	tmpInput.Close()

	// Test ParseSBOM
	bom, format, err := ParseSBOM(tmpInput.Name())
	if err != nil {
		t.Fatalf("ParseSBOM failed: %v", err)
	}

	if format != cdx.BOMFileFormatJSON {
		t.Errorf("Expected JSON format, got %v", format)
	}

	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("Expected 1 component, got %v", bom.Components)
	}

	comp := (*bom.Components)[0]
	if comp.Name != "test-component" {
		t.Errorf("Expected component name 'test-component', got %q", comp.Name)
	}

	// Add copyright evidence to component
	evidenceCopyright := []cdx.Copyright{
		{Text: "Copyright (c) 2026 Test Authors"},
		{Text: "Copyright (c) 2024 Contributor LLC"},
	}
	(*bom.Components)[0].Evidence = &cdx.Evidence{
		Copyright: &evidenceCopyright,
	}

	// Test SaveSBOM
	tmpOutput, err := os.CreateTemp("", "sbom-output-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp output file: %v", err)
	}
	outputName := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputName)

	if err := SaveSBOM(bom, format, outputName); err != nil {
		t.Fatalf("SaveSBOM failed: %v", err)
	}

	// Verify output
	savedBOM, savedFormat, err := ParseSBOM(outputName)
	if err != nil {
		t.Fatalf("Failed to parse saved SBOM: %v", err)
	}

	if savedFormat != cdx.BOMFileFormatJSON {
		t.Errorf("Expected saved format JSON, got %v", savedFormat)
	}

	if savedBOM.Components == nil || len(*savedBOM.Components) != 1 {
		t.Fatalf("Expected 1 component in saved SBOM")
	}

	savedComp := (*savedBOM.Components)[0]
	if savedComp.Evidence == nil || savedComp.Evidence.Copyright == nil || len(*savedComp.Evidence.Copyright) != 2 {
		t.Fatalf("Expected 2 copyright evidence entries, got %v", savedComp.Evidence)
	}

	if (*savedComp.Evidence.Copyright)[0].Text != "Copyright (c) 2026 Test Authors" {
		t.Errorf("First copyright text mismatch: %s", (*savedComp.Evidence.Copyright)[0].Text)
	}
}

func TestDetectFormat(t *testing.T) {
	jsonInput := `   {"bomFormat": "CycloneDX"}`
	format, _, err := DetectFormat(strings.NewReader(jsonInput))
	if err != nil || format != cdx.BOMFileFormatJSON {
		t.Errorf("Expected JSON, got %v (err: %v)", format, err)
	}

	xmlInput := `   <?xml version="1.0" encoding="UTF-8"?><bom>`
	format, _, err = DetectFormat(strings.NewReader(xmlInput))
	if err != nil || format != cdx.BOMFileFormatXML {
		t.Errorf("Expected XML, got %v (err: %v)", format, err)
	}
}
