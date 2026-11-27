package aibom

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func TestLoadAIBOMConfigAndInjectPreservesExistingComponents(t *testing.T) {
	root := t.TempDir()
	modelHash := strings.Repeat("1", 64)
	yamlContent := `version: "1"
components:
  - name: "qwen3-coder-local"
    type: "machine-learning-model"
    version: "32b-q4"
    provider: "local-ollama"
    sha256: "` + modelHash + `"
    airgap_capable: true
    license: "Apache-2.0"
    url: "https://example.invalid/models/qwen3"
    properties:
      quantization: "Q4_K_M"
  - name: "coppermind-mcp"
    type: "mcp-server"
    version: "0.9.0"
    provider: "bonjoski"
    airgap_capable: true
`
	if err := os.WriteFile(filepath.Join(root, ".ai-bom.yaml"), []byte(yamlContent), 0600); err != nil {
		t.Fatalf("write .ai-bom.yaml: %v", err)
	}

	cfg, err := LoadAIBOMConfig(root, ".ai-bom.yaml")
	if err != nil {
		t.Fatalf("LoadAIBOMConfig failed: %v", err)
	}
	if len(cfg.Components) != 2 {
		t.Fatalf("expected 2 AI components, got %d", len(cfg.Components))
	}

	origHash := strings.Repeat("b", 64)
	baseSBOM := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:golang/github.com/google/uuid@v1.6.0",
      "name": "github.com/google/uuid",
      "version": "v1.6.0",
      "copyright": "Copyright (c) 2009,2014 Google Inc.",
      "hashes": [
        { "alg": "SHA-256", "content": "` + origHash + `" }
      ]
    }
  ]
}`

	enrichedJSON, err := InjectAIBOMJSON([]byte(baseSBOM), cfg)
	if err != nil {
		t.Fatalf("InjectAIBOMJSON failed: %v", err)
	}

	outBOM := cdx.NewBOM()
	if err := cdx.NewBOMDecoder(bytes.NewReader(enrichedJSON), cdx.BOMFileFormatJSON).Decode(outBOM); err != nil {
		t.Fatalf("decode enriched SBOM: %v", err)
	}

	if outBOM.SpecVersion != cdx.SpecVersion1_6 {
		t.Errorf("expected specVersion 1.6, got %v", outBOM.SpecVersion)
	}
	if outBOM.Components == nil || len(*outBOM.Components) != 3 {
		t.Fatalf("expected 3 components (1 original + 2 AI), got %d", len(*outBOM.Components))
	}

	// Verify existing component hash & copyright were NOT mutated.
	orig := (*outBOM.Components)[0]
	if orig.Copyright != "Copyright (c) 2009,2014 Google Inc." {
		t.Errorf("existing copyright mutated: %q", orig.Copyright)
	}
	if orig.Hashes == nil || len(*orig.Hashes) != 1 || (*orig.Hashes)[0].Value != origHash {
		t.Errorf("existing hash mutated: %+v", orig.Hashes)
	}

	// Verify ML model component.
	ml := (*outBOM.Components)[1]
	if ml.Type != cdx.ComponentTypeMachineLearningModel {
		t.Errorf("expected type machine-learning-model, got %q", ml.Type)
	}
	if ml.ModelCard == nil {
		t.Errorf("expected ModelCard on machine-learning-model component")
	}
	if ml.Hashes == nil || (*ml.Hashes)[0].Value != modelHash {
		t.Errorf("expected SHA-256 hash on model component, got %+v", ml.Hashes)
	}

	// Verify MCP server component maps to CycloneDX application with properties.
	mcp := (*outBOM.Components)[2]
	if mcp.Type != cdx.ComponentTypeApplication {
		t.Errorf("expected type application for mcp-server, got %q", mcp.Type)
	}
	if mcp.Properties == nil || len(*mcp.Properties) < 2 {
		t.Errorf("expected properties on mcp-server component")
	}
}

func TestLoadAIBOMConfig_RejectsSymlinkAndTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	secretOutside := filepath.Join(outside, "outside.yaml")
	if err := os.WriteFile(secretOutside, []byte("components: []\n"), 0600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	// 1. Direct symlink inside root pointing outside
	symPath := filepath.Join(root, ".ai-bom.yaml")
	if err := os.Symlink(secretOutside, symPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := LoadAIBOMConfig(root, ".ai-bom.yaml"); !errors.Is(err, ErrSymlinkRejected) {
		t.Errorf("expected ErrSymlinkRejected for symlinked .ai-bom.yaml, got: %v", err)
	}

	// 2. Parent traversal '..'
	if _, err := LoadAIBOMConfig(root, "../outside.yaml"); !errors.Is(err, ErrPathTraversal) {
		t.Errorf("expected ErrPathTraversal for '..', got: %v", err)
	}

	// 3. Absolute path
	if _, err := LoadAIBOMConfig(root, secretOutside); !errors.Is(err, ErrPathTraversal) {
		t.Errorf("expected ErrPathTraversal for absolute path, got: %v", err)
	}

	// 4. Symlinked subdirectory inside root
	subLink := filepath.Join(root, "sublink")
	if err := os.Symlink(outside, subLink); err != nil {
		t.Fatalf("symlink subdir: %v", err)
	}
	if _, err := LoadAIBOMConfig(root, "sublink/outside.yaml"); !errors.Is(err, ErrSymlinkRejected) {
		t.Errorf("expected ErrSymlinkRejected for symlinked parent dir, got: %v", err)
	}
}
