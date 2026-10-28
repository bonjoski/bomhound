package parser_test

import (
	"path/filepath"
	"testing"

	"github.com/bonjoski/bomhound/internal/parser"
)

func TestStandardSampleSBOMFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "sample-sbom.cdx.json")

	bom, format, err := parser.ParseSBOM(fixturePath)
	if err != nil {
		t.Fatalf("Failed to load standard test fixture %s: %v", fixturePath, err)
	}

	if format != 1 { // cdx.BOMFileFormatJSON == 1
		t.Errorf("Expected JSON format, got %v", format)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("Expected BOMFormat 'CycloneDX', got '%s'", bom.BOMFormat)
	}

	if bom.SpecVersion.String() != "1.5" {
		t.Errorf("Expected SpecVersion '1.5', got '%s'", bom.SpecVersion.String())
	}

	if bom.Components == nil || len(*bom.Components) != 3 {
		t.Fatalf("Expected 3 components, got %d", len(*bom.Components))
	}

	expectedPURLs := map[string]bool{
		"pkg:golang/github.com/google/uuid@v1.6.0": true,
		"pkg:golang/golang.org/x/crypto@v0.21.0":   true,
		"pkg:npm/react@18.2.0":                     true,
	}

	for _, comp := range *bom.Components {
		if !expectedPURLs[comp.PackageURL] {
			t.Errorf("Unexpected component PURL: %s", comp.PackageURL)
		}
	}
}
