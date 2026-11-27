package cra

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bonjoski/bomhound/pkg/vex"
)

type testBundleFixture struct {
	root       string
	binaryPath string
	sbomPath   string
	vexPath    string
	slsaPath   string
	riskPath   string
	aibomPath  string
	pubKey     ed25519.PublicKey
	privKey    ed25519.PrivateKey
	binSHA256  string
}

func makeSignedSLSA(t *testing.T, subjectName, subjectSHA256 string, priv ed25519.PrivateKey) []byte {
	t.Helper()
	stmt := map[string]any{
		"_type": vex.InTotoStatementTypeV1,
		"subject": []map[string]any{
			{
				"name":   subjectName,
				"digest": map[string]string{"sha256": subjectSHA256},
			},
		},
		"predicateType": SLSAPredicateTypeV1,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType": "https://bonjoski.github.io/soulcaster/build/v1",
				"externalParameters": map[string]any{
					"command": []string{"go", "build", "-trimpath"},
				},
			},
		},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal SLSA statement: %v", err)
	}
	pae := vex.ComputePAE(vex.DSSEPayloadTypeInToto, payload)
	sig := ed25519.Sign(priv, pae)
	pub := priv.Public().(ed25519.PublicKey)

	env := vex.DSSEEnvelope{
		PayloadType: vex.DSSEPayloadTypeInToto,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []vex.DSSESignature{
			{
				KeyID: vex.KeyIDForPublicKey(pub),
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal SLSA DSSE: %v", err)
	}
	return append(out, '\n')
}

func createValidFixture(t *testing.T) *testBundleFixture {
	t.Helper()
	root := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	binPath := filepath.Join(root, "myapp")
	if err := os.WriteFile(binPath, []byte("hermetic-release-binary-v1.0.0"), 0600); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	binSHA, err := vex.HashFileSHA256(binPath)
	if err != nil {
		t.Fatalf("hash binary: %v", err)
	}

	sbomPath := filepath.Join(root, "sbom-enriched.cdx.json")
	sbomJSON := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:golang/github.com/google/uuid@v1.6.0",
      "name": "github.com/google/uuid",
      "version": "v1.6.0",
      "copyright": "Copyright (c) 2009 Google Inc."
    }
  ]
}`
	if err := os.WriteFile(sbomPath, []byte(sbomJSON), 0600); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	doc := vex.NewOpenVEXDocument("bomhound-cra-test")
	doc.Statements = append(doc.Statements, vex.Statement{
		Vulnerability: vex.VulnerabilityIdent{Name: "CVE-2026-12345"},
		Products:      []string{"pkg:generic/myapp@1.0.0"},
		Status:        vex.StatusNotAffected,
		Justification: vex.JustificationVulnerableCodeNotPresent,
	})
	vexBytes, err := vex.SignOpenVEX(doc, vex.SignedVEXOptions{
		ArtifactPath: binPath,
		PrivateKey:   priv,
	})
	if err != nil {
		t.Fatalf("SignOpenVEX: %v", err)
	}
	vexPath := filepath.Join(root, "myapp.vex.dsse.json")
	if err := os.WriteFile(vexPath, vexBytes, 0600); err != nil {
		t.Fatalf("write vex: %v", err)
	}

	slsaBytes := makeSignedSLSA(t, "myapp", binSHA, priv)
	slsaPath := filepath.Join(root, "myapp.intoto.jsonl")
	if err := os.WriteFile(slsaPath, slsaBytes, 0600); err != nil {
		t.Fatalf("write slsa: %v", err)
	}

	riskPath := filepath.Join(root, "cra-risk.yaml")
	riskYAML := `standard: "BS EN 40000-1-2:2026"
product: "myapp"
support_period_months: 60
threat_model: "STRIDE reviewed; air-gapped local workstation CLI"
`
	if err := os.WriteFile(riskPath, []byte(riskYAML), 0600); err != nil {
		t.Fatalf("write risk: %v", err)
	}

	aibomPath := filepath.Join(root, ".ai-bom.yaml")
	aibomYAML := `version: "1"
components:
  - name: "local-embedder"
    type: "machine-learning-model"
    version: "1.0.0"
    airgap_capable: true
`
	if err := os.WriteFile(aibomPath, []byte(aibomYAML), 0600); err != nil {
		t.Fatalf("write ai-bom: %v", err)
	}

	return &testBundleFixture{
		root:       root,
		binaryPath: binPath,
		sbomPath:   sbomPath,
		vexPath:    vexPath,
		slsaPath:   slsaPath,
		riskPath:   riskPath,
		aibomPath:  aibomPath,
		pubKey:     pub,
		privKey:    priv,
		binSHA256:  binSHA,
	}
}

func TestAdversarial_MixAndMatchDigestTampering(t *testing.T) {
	fx := createValidFixture(t)
	epoch := int64(1764201600)

	// 1. Trojanized binary paired with valid old VEX + old SLSA
	trojanBin := filepath.Join(fx.root, "trojan-app")
	if err := os.WriteFile(trojanBin, []byte("trojanized-payload-bytes"), 0600); err != nil {
		t.Fatalf("write trojan binary: %v", err)
	}

	_, err := BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:   fx.root,
		BinaryPath:      trojanBin,
		SBOMPath:        fx.sbomPath,
		VEXDSSEPath:     fx.vexPath,
		SLSAIntotoPath:  fx.slsaPath,
		OutputTarGz:     filepath.Join(fx.root, "tampered-bin.tar.gz"),
		VEXPublicKey:    fx.pubKey,
		SourceDateEpoch: &epoch,
	})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch for trojanized binary, got: %v", err)
	}

	// 2. Valid binary + valid VEX, but SLSA provenance attests a different binary digest
	otherDigest := strings.Repeat("f", 64)
	mismatchSLSA := filepath.Join(fx.root, "old.intoto.jsonl")
	if err := os.WriteFile(mismatchSLSA, makeSignedSLSA(t, "myapp", otherDigest, fx.privKey), 0600); err != nil {
		t.Fatalf("write mismatched SLSA: %v", err)
	}

	_, err = BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:   fx.root,
		BinaryPath:      fx.binaryPath,
		SBOMPath:        fx.sbomPath,
		VEXDSSEPath:     fx.vexPath,
		SLSAIntotoPath:  mismatchSLSA,
		OutputTarGz:     filepath.Join(fx.root, "tampered-slsa.tar.gz"),
		VEXPublicKey:    fx.pubKey,
		SourceDateEpoch: &epoch,
	})
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch for mix-and-match SLSA, got: %v", err)
	}
}

func TestAdversarial_ForgedDSSESignature(t *testing.T) {
	fx := createValidFixture(t)
	attackerPub, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = attackerPub

	// Attacker signs forged VEX claiming CVE not affected
	forgedDoc := vex.NewOpenVEXDocument("attacker")
	forgedVEX, err := vex.SignOpenVEX(forgedDoc, vex.SignedVEXOptions{
		ArtifactPath: fx.binaryPath,
		PrivateKey:   attackerPriv,
	})
	if err != nil {
		t.Fatalf("SignOpenVEX: %v", err)
	}
	forgedVEXPath := filepath.Join(fx.root, "forged.vex.dsse.json")
	if err := os.WriteFile(forgedVEXPath, forgedVEX, 0600); err != nil {
		t.Fatalf("write forged vex: %v", err)
	}

	_, err = BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:  fx.root,
		BinaryPath:     fx.binaryPath,
		SBOMPath:       fx.sbomPath,
		VEXDSSEPath:    forgedVEXPath,
		SLSAIntotoPath: fx.slsaPath,
		OutputTarGz:    filepath.Join(fx.root, "forged-vex.tar.gz"),
		VEXPublicKey:   fx.pubKey,
	})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for forged VEX signature, got: %v", err)
	}

	// Unsigned SLSA rejected when AllowUnsignedLocal is false
	unsignedSLSA := filepath.Join(fx.root, "unsigned.intoto.jsonl")
	rawStmt := fmt.Sprintf(`{"_type":%q,"subject":[{"name":"myapp","digest":{"sha256":%q}}],"predicateType":%q,"predicate":{}}`,
		vex.InTotoStatementTypeV1, fx.binSHA256, SLSAPredicateTypeV1)
	if err := os.WriteFile(unsignedSLSA, []byte(rawStmt), 0600); err != nil {
		t.Fatalf("write unsigned slsa: %v", err)
	}
	_, err = BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:  fx.root,
		BinaryPath:     fx.binaryPath,
		SBOMPath:       fx.sbomPath,
		VEXDSSEPath:    fx.vexPath,
		SLSAIntotoPath: unsignedSLSA,
		OutputTarGz:    filepath.Join(fx.root, "unsigned-slsa.tar.gz"),
		VEXPublicKey:   fx.pubKey,
	})
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for unsigned SLSA, got: %v", err)
	}
}

func TestAdversarial_SymlinkAndPathTraversal(t *testing.T) {
	fx := createValidFixture(t)
	outside := t.TempDir()
	outsideTarget := filepath.Join(outside, "secret.yaml")
	if err := os.WriteFile(outsideTarget, []byte("standard: BS EN 40000-1-2\n"), 0600); err != nil {
		t.Fatalf("write outside: %v", err)
	}

	// 1. Symlinked .ai-bom.yaml input
	symAIBOM := filepath.Join(fx.root, "sym-ai-bom.yaml")
	if err := os.Symlink(outsideTarget, symAIBOM); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, err := BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:  fx.root,
		BinaryPath:     fx.binaryPath,
		SBOMPath:       fx.sbomPath,
		VEXDSSEPath:    fx.vexPath,
		SLSAIntotoPath: fx.slsaPath,
		AIBOMPath:      symAIBOM,
		OutputTarGz:    filepath.Join(fx.root, "out1.tar.gz"),
		VEXPublicKey:   fx.pubKey,
	})
	if !errors.Is(err, ErrSymlinkViolation) {
		t.Fatalf("expected ErrSymlinkViolation for symlinked .ai-bom.yaml, got: %v", err)
	}

	// 2. Output symlink leaf attack
	symOut := filepath.Join(fx.root, "sym-out.tar.gz")
	if err := os.Symlink(filepath.Join(outside, "pwned.tar.gz"), symOut); err != nil {
		t.Fatalf("symlink out: %v", err)
	}
	_, err = BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:  fx.root,
		BinaryPath:     fx.binaryPath,
		SBOMPath:       fx.sbomPath,
		VEXDSSEPath:    fx.vexPath,
		SLSAIntotoPath: fx.slsaPath,
		OutputTarGz:    symOut,
		VEXPublicKey:   fx.pubKey,
	})
	if !errors.Is(err, ErrSymlinkViolation) {
		t.Fatalf("expected ErrSymlinkViolation for symlinked --out, got: %v", err)
	}

	// 3. Output '..' traversal attack
	_, err = BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:  fx.root,
		BinaryPath:     fx.binaryPath,
		SBOMPath:       fx.sbomPath,
		VEXDSSEPath:    fx.vexPath,
		SLSAIntotoPath: fx.slsaPath,
		OutputTarGz:    filepath.Join(fx.root, "..", "..", "etc", "cron.d", "evil.tar.gz"),
		VEXPublicKey:   fx.pubKey,
	})
	if !errors.Is(err, ErrSymlinkViolation) {
		t.Fatalf("expected ErrSymlinkViolation for '..' output traversal, got: %v", err)
	}
}

func TestAdversarial_SecretScrubberRejectsLeakedCredentials(t *testing.T) {
	fx := createValidFixture(t)

	// Construct synthetic credentials strictly via string concatenation to avoid static push-protection false hits.
	syntheticSecrets := []struct {
		name  string
		token string
	}{
		{name: "aws-key", token: "AKIA" + "IOSFODNN7EXAMPLE"},
		{name: "anthropic-key", token: "sk-" + "ant-api03-SyntheticTestToken9876543210"},
		{name: "github-pat", token: "ghp_" + "1234567890abcdefghijKLMNOPQRSTuv"},
		{name: "pem-key", token: "-----BEGIN " + "PRIVATE KEY-----\nMIIBVQIBADANBg"},
		{name: "high-entropy-assignment", token: "api_key: " + "Zx9Qp2Lm7Vr4Kw8Nj3Ht6Yb5Fc1Gd0"},
	}

	for _, tc := range syntheticSecrets {
		t.Run(tc.name, func(t *testing.T) {
			riskPath := filepath.Join(fx.root, "risk-"+tc.name+".yaml")
			body := "product: myapp\nnotes: " + tc.token + "\n"
			if err := os.WriteFile(riskPath, []byte(body), 0600); err != nil {
				t.Fatalf("write risk file: %v", err)
			}

			_, err := BuildCRABundle(CRABundleSpec{
				WorkspaceRoot:  fx.root,
				BinaryPath:     fx.binaryPath,
				SBOMPath:       fx.sbomPath,
				VEXDSSEPath:    fx.vexPath,
				SLSAIntotoPath: fx.slsaPath,
				RiskConfigPath: riskPath,
				OutputTarGz:    filepath.Join(fx.root, "secret-"+tc.name+".tar.gz"),
				VEXPublicKey:   fx.pubKey,
			})
			if !errors.Is(err, ErrSecretDetected) {
				t.Fatalf("expected ErrSecretDetected for %s, got: %v", tc.name, err)
			}
			// Ensure secret value itself is never leaked into the error string.
			if strings.Contains(err.Error(), tc.token) {
				t.Fatalf("error message echoed secret token!")
			}
		})
	}
}

func TestAdversarial_AntiTarSlipAndMaliciousArchives(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tmpDir := t.TempDir()

	writeMaliciousTarGz := func(name string, hdr *tar.Header, payload []byte) string {
		p := filepath.Join(tmpDir, name)
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if hdr.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(payload))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if len(payload) > 0 {
			if _, err := tw.Write(payload); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		_ = tw.Close()
		_ = gz.Close()
		if err := os.WriteFile(p, buf.Bytes(), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return p
	}

	cases := []struct {
		name string
		hdr  *tar.Header
		body []byte
	}{
		{
			name: "dotdot-slip.tar.gz",
			hdr:  &tar.Header{Name: "../evil.txt", Mode: 0644, Typeflag: tar.TypeReg},
			body: []byte("slip"),
		},
		{
			name: "abs-path.tar.gz",
			hdr:  &tar.Header{Name: "/etc/passwd", Mode: 0644, Typeflag: tar.TypeReg},
			body: []byte("root:x:0:0"),
		},
		{
			name: "symlink-entry.tar.gz",
			hdr:  &tar.Header{Name: "manifest.json", Linkname: "/etc/passwd", Mode: 0777, Typeflag: tar.TypeSymlink},
		},
		{
			name: "hardlink-entry.tar.gz",
			hdr:  &tar.Header{Name: "manifest.json", Linkname: "/etc/shadow", Mode: 0644, Typeflag: tar.TypeLink},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeMaliciousTarGz(tc.name, tc.hdr, tc.body)
			_, err := VerifyCRABundle(p, pub)
			if !errors.Is(err, ErrArchiveViolation) {
				t.Fatalf("expected ErrArchiveViolation for %s, got: %v", tc.name, err)
			}
		})
	}
}

func TestAdversarial_OversizedJSONBombRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tmpDir := t.TempDir()
	bombPath := filepath.Join(tmpDir, "json-bomb.tar.gz")

	// Construct a highly compressible 33 MiB JSON entry (> 32 MiB MaxEntryBytes) that compresses to ~35 KiB.
	const bombSize = MaxEntryBytes + (1 << 20)
	f, err := os.Create(bombPath)
	if err != nil {
		t.Fatalf("create bomb: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name:     EntrySBOM,
		Mode:     0644,
		Size:     bombSize,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	chunk := bytes.Repeat([]byte(" "), 64*1024)
	written := int64(0)
	for written < bombSize {
		toWrite := int64(len(chunk))
		if bombSize-written < toWrite {
			toWrite = bombSize - written
		}
		n, err := tw.Write(chunk[:toWrite])
		if err != nil {
			t.Fatalf("Write bomb chunk: %v", err)
		}
		written += int64(n)
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()

	_, err = VerifyCRABundle(bombPath, pub)
	if !errors.Is(err, ErrArchiveViolation) {
		t.Fatalf("expected ErrArchiveViolation for >32 MiB JSON bomb, got: %v", err)
	}
}

func TestAdversarial_DeterministicReproducibilityAndConcurrencyN8(t *testing.T) {
	fx := createValidFixture(t)
	epoch := int64(1764201600)

	// Build 2 sequential bundles and verify byte-for-byte identity.
	outA := filepath.Join(fx.root, "bundle-a.tar.gz")
	outB := filepath.Join(fx.root, "bundle-b.tar.gz")

	manifestA, err := BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:   fx.root,
		BinaryPath:      fx.binaryPath,
		SBOMPath:        fx.sbomPath,
		VEXDSSEPath:     fx.vexPath,
		SLSAIntotoPath:  fx.slsaPath,
		RiskConfigPath:  fx.riskPath,
		AIBOMPath:       fx.aibomPath,
		OutputTarGz:     outA,
		VEXPublicKey:    fx.pubKey,
		SourceDateEpoch: &epoch,
	})
	if err != nil {
		t.Fatalf("BuildCRABundle A failed: %v", err)
	}
	if manifestA.SchemaVersion != SchemaVersion {
		t.Errorf("got schema_version=%q, want %q", manifestA.SchemaVersion, SchemaVersion)
	}
	if manifestA.SubjectName != "myapp" {
		t.Errorf("expected host-path-stripped SubjectName 'myapp', got %q", manifestA.SubjectName)
	}
	if len(manifestA.DeferredClauses) != 1 || manifestA.DeferredClauses[0] != "BS EN 40000-1-3 (pending BSI 2027)" {
		t.Errorf("unexpected DeferredClauses: %v", manifestA.DeferredClauses)
	}

	_, err = BuildCRABundle(CRABundleSpec{
		WorkspaceRoot:   fx.root,
		BinaryPath:      fx.binaryPath,
		SBOMPath:        fx.sbomPath,
		VEXDSSEPath:     fx.vexPath,
		SLSAIntotoPath:  fx.slsaPath,
		RiskConfigPath:  fx.riskPath,
		AIBOMPath:       fx.aibomPath,
		OutputTarGz:     outB,
		VEXPublicKey:    fx.pubKey,
		SourceDateEpoch: &epoch,
	})
	if err != nil {
		t.Fatalf("BuildCRABundle B failed: %v", err)
	}

	bytesA, err := os.ReadFile(outA)
	if err != nil {
		t.Fatalf("read A: %v", err)
	}
	bytesB, err := os.ReadFile(outB)
	if err != nil {
		t.Fatalf("read B: %v", err)
	}
	if !bytes.Equal(bytesA, bytesB) {
		t.Fatalf("expected deterministic byte-identical tar.gz bundles, got differing outputs")
	}

	expectedBundleSHA := sha256.Sum256(bytesA)
	expectedBundleHex := hex.EncodeToString(expectedBundleSHA[:])

	// Verify valid bundle passes VerifyCRABundle.
	res, err := VerifyCRABundle(outA, fx.pubKey)
	if err != nil {
		t.Fatalf("VerifyCRABundle failed: %v", err)
	}
	if res.ArtifactCount != 5 { // sbom, vex, provenance, risk, ai-bom
		t.Errorf("expected 5 artifacts, got %d", res.ArtifactCount)
	}

	// N=8 parallel subagent concurrency stress test under -race.
	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			outPath := filepath.Join(fx.root, fmt.Sprintf("concurrent-%d.tar.gz", id))
			if _, err := BuildCRABundle(CRABundleSpec{
				WorkspaceRoot:   fx.root,
				BinaryPath:      fx.binaryPath,
				SBOMPath:        fx.sbomPath,
				VEXDSSEPath:     fx.vexPath,
				SLSAIntotoPath:  fx.slsaPath,
				RiskConfigPath:  fx.riskPath,
				AIBOMPath:       fx.aibomPath,
				OutputTarGz:     outPath,
				VEXPublicKey:    fx.pubKey,
				SourceDateEpoch: &epoch,
			}); err != nil {
				errCh <- fmt.Errorf("worker %d build: %w", id, err)
				return
			}
			raw, err := os.ReadFile(outPath)
			if err != nil {
				errCh <- fmt.Errorf("worker %d read: %w", id, err)
				return
			}
			sum := sha256.Sum256(raw)
			if got := hex.EncodeToString(sum[:]); got != expectedBundleHex {
				errCh <- fmt.Errorf("worker %d non-deterministic digest %s != %s", id, got, expectedBundleHex)
				return
			}
			if _, err := VerifyCRABundle(outPath, fx.pubKey); err != nil {
				errCh <- fmt.Errorf("worker %d verify: %w", id, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
