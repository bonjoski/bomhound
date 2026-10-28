package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// TestAdversarial_SymlinkTraversal verifies that SaveSBOM strictly refuses
// to write through a symbolic link (preventing arbitrary file overwrite attacks).
func TestAdversarial_SymlinkTraversal(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bomhound-symlink-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create sensitive target file
	sensitivePath := filepath.Join(tempDir, "sensitive-file.txt")
	originalContent := "CRITICAL_SECRET_DATA"
	if err := os.WriteFile(sensitivePath, []byte(originalContent), 0600); err != nil {
		t.Fatalf("Failed to create sensitive file: %v", err)
	}

	// Create symlink pointing to sensitive target
	symlinkPath := filepath.Join(tempDir, "symlink-target.cdx.json")
	if err := os.Symlink(sensitivePath, symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Attempt to overwrite symlink via SaveSBOM
	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{
		{Name: "malicious-payload", PackageURL: "pkg:npm/malicious@1.0.0"},
	}

	err = SaveSBOM(bom, cdx.BOMFileFormatJSON, symlinkPath)
	if err == nil {
		t.Fatalf("Adversarial attack succeeded: SaveSBOM followed symlink and overwrote target!")
	}

	if !strings.Contains(err.Error(), "refusing to write to symlink") {
		t.Errorf("Expected 'refusing to write to symlink' error, got: %v", err)
	}

	// Verify sensitive file was NOT touched
	content, err := os.ReadFile(sensitivePath)
	if err != nil {
		t.Fatalf("Failed to read sensitive file: %v", err)
	}
	if string(content) != originalContent {
		t.Fatalf("Sensitive file was corrupted! Got: %s", string(content))
	}
}

// TestAdversarial_MalformedAndTruncatedJSON verifies that corrupt or hostile
// JSON inputs fail gracefully with structured errors without crashing or panicking.
func TestAdversarial_MalformedAndTruncatedJSON(t *testing.T) {
	corruptPayloads := []struct {
		name    string
		payload string
	}{
		{"Empty string", ""},
		{"Whitespace only", "   \t\n   "},
		{"Truncated JSON object", `{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [`},
		{"Invalid brackets", `{"bomFormat": "CycloneDX", "components": }`},
		{"Null byte injection", "\x00\x00{\"bomFormat\": \"CycloneDX\"}"},
		{"Non-JSON binary junk", string([]byte{0xFF, 0xFE, 0x00, 0x12, 0x34, 0x56})},
		{"Invalid UTF-8 sequence", "{\"bomFormat\": \"CycloneDX\", \"components\": [\"" + string([]byte{0x80, 0x81, 0x82}) + "\"]}"},
	}

	for _, tt := range corruptPayloads {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseSBOMReader(strings.NewReader(tt.payload))
			if err == nil {
				t.Errorf("Expected error for corrupt input %q, but got nil", tt.name)
			}
		})
	}
}

// TestAdversarial_PathTraversalAndHostilePURLs ensures pathological PURLs do not cause panics.
func TestAdversarial_PathTraversalAndHostilePURLs(t *testing.T) {
	hostilePURLs := []string{
		"pkg:golang/../../../../etc/passwd",
		"pkg:npm/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
		"pkg:../../../../windows/system32/cmd.exe",
		"pkg:\x00evil/name",
		"pkg:golang/" + strings.Repeat("a", 10000) + "@v1.0.0",
		"pkg:golang/github.com/foo/bar@v1.0.0?repository_url=http://169.254.169.254",
	}

	for _, p := range hostilePURLs {
		pkgType := GetPackageType(p)
		// Should not panic, should return a string
		if pkgType == "" {
			t.Errorf("Expected non-empty package type fallback for %q", p)
		}
	}
}

// TestAdversarial_CycloneDXMetadataPreservation verifies that all complex metadata,
// custom properties, dependency graphs, and tools are preserved during round-trip.
func TestAdversarial_CycloneDXMetadataPreservation(t *testing.T) {
	originalJSON := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 42,
  "metadata": {
    "timestamp": "2026-10-28T12:00:00Z",
    "tools": [
      {
        "vendor": "SecurityCorp",
        "name": "scanner",
        "version": "9.9.9"
      }
    ],
    "properties": [
      {
        "name": "enterprise:build_id",
        "value": "build-897123"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "secure-lib",
      "version": "1.0.0",
      "purl": "pkg:npm/secure-lib@1.0.0",
      "properties": [
        {
          "name": "compliance:reviewed",
          "value": "true"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:npm/secure-lib@1.0.0",
      "dependsOn": []
    }
  ]
}`

	bom, format, err := ParseSBOMReader(strings.NewReader(originalJSON))
	if err != nil {
		t.Fatalf("Failed to parse complex SBOM: %v", err)
	}

	// Verify metadata and properties are populated
	if bom.Metadata == nil || bom.Metadata.Properties == nil || len(*bom.Metadata.Properties) != 1 {
		t.Fatalf("Metadata properties lost: %v", bom.Metadata)
	}
	if (*bom.Metadata.Properties)[0].Name != "enterprise:build_id" {
		t.Errorf("Property name mismatch: %s", (*bom.Metadata.Properties)[0].Name)
	}

	// Verify dependencies preserved
	if bom.Dependencies == nil || len(*bom.Dependencies) != 1 {
		t.Fatalf("Dependencies lost: %v", bom.Dependencies)
	}

	// Round-trip serialize
	var buf strings.Builder
	if err := EncodeSBOM(bom, format, &buf); err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	roundtrip := buf.String()
	if !strings.Contains(roundtrip, "enterprise:build_id") {
		t.Errorf("Metadata property missing in roundtrip output")
	}
	if !strings.Contains(roundtrip, "dependencies") {
		t.Errorf("Dependencies array missing in roundtrip output")
	}
}
