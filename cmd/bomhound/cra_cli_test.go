package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/bomhound/pkg/cra"
	"github.com/bonjoski/bomhound/pkg/vex"
)

func TestCRACLI_EndToEndAndExit10OnTampering(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Generate release binary & keypair
	binPath := filepath.Join(tmpDir, "demo-cli")
	if err := os.WriteFile(binPath, []byte("demo-cli-release-v1.0.0"), 0600); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	binSHA, err := vex.HashFileSHA256(binPath)
	if err != nil {
		t.Fatalf("hash binary: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privPEM, _ := vex.EncodeEd25519PrivateKeyPEM(priv)
	keyPath := filepath.Join(tmpDir, "release.key")
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	pubOutPath := filepath.Join(tmpDir, "release.pub")

	// 2. bomhound enrich --offline --ai-bom
	sbomIn := filepath.Join(tmpDir, "sbom.cdx.json")
	sbomRaw := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","bom-ref":"pkg:golang/example/lib@v1.0.0","name":"example/lib","version":"v1.0.0","copyright":"Copyright 2026 Example"}]}`
	if err := os.WriteFile(sbomIn, []byte(sbomRaw), 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	aibomYAML := "version: \"1\"\ncomponents:\n  - name: \"local-llm\"\n    type: \"machine-learning-model\"\n    version: \"1.0\"\n    airgap_capable: true\n"
	if err := os.WriteFile(filepath.Join(tmpDir, ".ai-bom.yaml"), []byte(aibomYAML), 0600); err != nil {
		t.Fatalf("write ai-bom: %v", err)
	}
	sbomOut := filepath.Join(tmpDir, "sbom-enriched.cdx.json")
	if code := runEnrich([]string{
		"--offline",
		"--root", tmpDir,
		"--input", sbomIn,
		"--ai-bom", ".ai-bom.yaml",
		"--output", sbomOut,
	}); code != 0 {
		t.Fatalf("runEnrich failed with exit code %d", code)
	}
	enrichedBytes, err := os.ReadFile(sbomOut)
	if err != nil {
		t.Fatalf("read enriched sbom: %v", err)
	}
	if !strings.Contains(string(enrichedBytes), "machine-learning-model") || !strings.Contains(string(enrichedBytes), "Copyright 2026 Example") {
		t.Fatalf("enriched SBOM missing AI-BOM or mutated existing copyright: %s", string(enrichedBytes))
	}

	// 3. bomhound vex --sign --binary --key --pubkey-out
	vexOut := filepath.Join(tmpDir, "demo-cli.vex.dsse.json")
	if code := runVEX([]string{
		"--sign",
		"--binary", binPath,
		"--key", keyPath,
		"--pubkey-out", pubOutPath,
		"--output", vexOut,
	}); code != 0 {
		t.Fatalf("runVEX --sign failed with exit code %d", code)
	}

	// Verify via CLI
	if code := runVEX([]string{
		"--verify",
		"--binary", binPath,
		"--pubkey", pubOutPath,
		vexOut,
	}); code != 0 {
		t.Fatalf("runVEX --verify failed with exit code %d", code)
	}

	// 4. Create matching Soulcaster SLSA DSSE .intoto.jsonl
	slsaStmt := map[string]any{
		"_type":         vex.InTotoStatementTypeV1,
		"subject":       []map[string]any{{"name": "demo-cli", "digest": map[string]string{"sha256": binSHA}}},
		"predicateType": cra.SLSAPredicateTypeV1,
		"predicate":     map[string]any{"buildDefinition": map[string]any{"buildType": "https://bonjoski.github.io/soulcaster/build/v1"}},
	}
	slsaPayload, _ := json.Marshal(slsaStmt)
	slsaSig := ed25519.Sign(priv, vex.ComputePAE(vex.DSSEPayloadTypeInToto, slsaPayload))
	slsaEnv, _ := json.Marshal(vex.DSSEEnvelope{
		PayloadType: vex.DSSEPayloadTypeInToto,
		Payload:     base64.StdEncoding.EncodeToString(slsaPayload),
		Signatures:  []vex.DSSESignature{{KeyID: vex.KeyIDForPublicKey(pub), Sig: base64.StdEncoding.EncodeToString(slsaSig)}},
	})
	slsaPath := filepath.Join(tmpDir, "demo-cli.intoto.jsonl")
	if err := os.WriteFile(slsaPath, append(slsaEnv, '\n'), 0600); err != nil {
		t.Fatalf("write slsa: %v", err)
	}

	// 5. bomhound bundle --cra & bomhound bundle --verify
	bundleOut := filepath.Join(tmpDir, "demo-cli-v1.0.0-cra-evidence.tar.gz")
	if code := runBundle([]string{
		"--cra",
		"--root", tmpDir,
		"--binary", binPath,
		"--sbom", sbomOut,
		"--vex", vexOut,
		"--provenance", slsaPath,
		"--pubkey", pubOutPath,
		"--out", bundleOut,
	}); code != 0 {
		t.Fatalf("runBundle --cra failed with exit code %d", code)
	}

	// Verify with positional bundle path BEFORE --pubkey flag
	if code := runBundle([]string{
		"--verify",
		bundleOut,
		"--pubkey", pubOutPath,
		"--binary", binPath,
	}); code != 0 {
		t.Fatalf("runBundle --verify failed with exit code %d", code)
	}

	// 6. Tampered binary MUST exit 10 (fail-closed mix-and-match protection)
	tamperedBin := filepath.Join(tmpDir, "tampered-cli")
	if err := os.WriteFile(tamperedBin, []byte("tampered-binary-bytes"), 0600); err != nil {
		t.Fatalf("write tampered bin: %v", err)
	}
	if code := runBundle([]string{
		"--cra",
		"--root", tmpDir,
		"--binary", tamperedBin,
		"--sbom", sbomOut,
		"--vex", vexOut,
		"--provenance", slsaPath,
		"--pubkey", pubOutPath,
		"--out", filepath.Join(tmpDir, "should-not-exist.tar.gz"),
	}); code != cra.ExitCodeDigestMismatch {
		t.Fatalf("expected exit code %d on digest mismatch, got %d", cra.ExitCodeDigestMismatch, code)
	}

	if code := runBundle([]string{
		"--verify",
		bundleOut,
		"--pubkey", pubOutPath,
		"--binary", tamperedBin,
	}); code != cra.ExitCodeDigestMismatch {
		t.Fatalf("expected exit code %d on verify binary mismatch, got %d", cra.ExitCodeDigestMismatch, code)
	}
}
