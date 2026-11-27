package cra

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bonjoski/bomhound/pkg/vex"
)

const (
	// SchemaVersion is the CRA offline lifecycle evidence manifest schema version.
	SchemaVersion = "cra-evidence-v1"

	// DefaultStandardVersion is the human-readable standards descriptor for BS EN 40000-1-1 / 1-2.
	DefaultStandardVersion = "BS EN 40000-1-1:2026 / BS EN 40000-1-2:2026"

	// SLSAPredicateTypeV1 is the SLSA v1.0 Provenance predicateType URI.
	SLSAPredicateTypeV1 = "https://slsa.dev/provenance/v1"

	// ExitCodeDigestMismatch is the fail-closed CLI exit code for subject-digest mix-and-match tampering.
	ExitCodeDigestMismatch = 10

	// MaxEntryBytes caps any individual bundle entry or attestation JSON to 32 MiB.
	MaxEntryBytes = 32 << 20

	// MaxArchiveBytes caps total decompressed archive payload to 128 MiB.
	MaxArchiveBytes = 128 << 20

	// Archive entry filenames (always normalized, zero host path leakage).
	EntryManifest   = "manifest.json"
	EntrySBOM       = "sbom.cdx.json"
	EntryVEX        = "vex.dsse.json"
	EntryProvenance = "provenance.intoto.jsonl"
	EntryRiskConfig = "cra-risk.yaml"
	EntryAIBOM      = "ai-bom.yaml"
)

var (
	// DefaultStandards lists the BSI horizontal EU CRA standards satisfied by this bundle.
	DefaultStandards = []string{"BS EN 40000-1-1:2026", "BS EN 40000-1-2:2026"}

	// DefaultDeferredClauses explicitly records pending standards deferred until publication.
	DefaultDeferredClauses = []string{"BS EN 40000-1-3 (pending BSI 2027)"}

	// ErrDigestMismatch indicates a mix-and-match subject SHA-256 mismatch across binary/VEX/SLSA/manifest.
	ErrDigestMismatch = errors.New("CRA evidence subject SHA-256 digest mismatch")

	// ErrSignatureInvalid indicates missing or invalid DSSE cryptographic signature.
	ErrSignatureInvalid = errors.New("CRA evidence DSSE signature verification failed")

	// ErrSymlinkViolation indicates a symlink or path-traversal violation on input or output paths.
	ErrSymlinkViolation = errors.New("symlink or path traversal violation")

	// ErrArchiveViolation indicates a malformed, oversized, or tar-slip archive.
	ErrArchiveViolation = errors.New("CRA evidence archive integrity or safety violation")
)

// CRABundleSpec defines all inputs and policy options for assembling an offline CRA evidence bundle.
type CRABundleSpec struct {
	StandardVersion    string            // Defaults to DefaultStandardVersion
	WorkspaceRoot      string            // Optional workspace root for os.OpenRoot confinement
	BinaryPath         string            // Release binary whose SHA-256 is cross-verified
	SBOMPath           string            // CycloneDX SBOM JSON
	VEXDSSEPath        string            // DSSE-signed OpenVEX file
	SLSAIntotoPath     string            // Soulcaster SLSA .intoto.jsonl file
	RiskConfigPath     string            // Optional cra-risk.yaml lifecycle risk metadata
	AIBOMPath          string            // Optional .ai-bom.yaml metadata
	OutputTarGz        string            // Destination .tar.gz path (written atomically)
	VEXPublicKey       ed25519.PublicKey // Trusted Ed25519 public key for VEX DSSE verification
	SLSAPublicKey      ed25519.PublicKey // Optional Ed25519 public key for SLSA DSSE verification (defaults to VEXPublicKey)
	AllowUnsignedLocal bool              // Explicit dry-run override for unsigned local attestations (default false)
	SourceDateEpoch    *int64            // Optional deterministic UNIX timestamp override
}

// CRAManifest is the tamper-evident manifest written as manifest.json inside the CRA bundle.
type CRAManifest struct {
	SchemaVersion   string            `json:"schema_version"`
	Standards       []string          `json:"standards"`
	SubjectName     string            `json:"subject_name"`
	SubjectSHA256   string            `json:"subject_sha256"`
	Artifacts       map[string]string `json:"artifacts"`
	DeferredClauses []string          `json:"deferred_clauses"`
	GeneratedAt     string            `json:"generated_at"`
}

// VerifyOptions customizes offline CRA bundle verification.
type VerifyOptions struct {
	VEXPublicKey       ed25519.PublicKey
	SLSAPublicKey      ed25519.PublicKey
	ExpectedBinaryPath string
	AllowUnsignedLocal bool
}

// VerifyResult reports verified CRA bundle metadata on successful verification.
type VerifyResult struct {
	Manifest      *CRAManifest
	ArtifactCount int
	VerifiedVEX   bool
	VerifiedSLSA  bool
}

type genericInTotoStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// BuildCRABundle cross-verifies binary, DSSE OpenVEX, Soulcaster SLSA provenance, SBOM, and optional
// lifecycle risk metadata, then writes a deterministic, atomic .tar.gz CRA evidence bundle.
func BuildCRABundle(spec CRABundleSpec) (*CRAManifest, error) {
	if strings.TrimSpace(spec.BinaryPath) == "" {
		return nil, errors.New("BinaryPath is required")
	}
	if strings.TrimSpace(spec.SBOMPath) == "" {
		return nil, errors.New("SBOMPath is required")
	}
	if strings.TrimSpace(spec.VEXDSSEPath) == "" {
		return nil, errors.New("VEXDSSEPath is required")
	}
	if strings.TrimSpace(spec.SLSAIntotoPath) == "" {
		return nil, errors.New("SLSAIntotoPath is required")
	}
	if strings.TrimSpace(spec.OutputTarGz) == "" {
		return nil, errors.New("OutputTarGz is required")
	}

	if err := validateOutputPath(spec.WorkspaceRoot, spec.OutputTarGz); err != nil {
		return nil, err
	}

	// 1. Compute exact SHA-256 of release binary (refusing symlinks & escapes).
	binarySHA256, err := hashInputFile(spec.WorkspaceRoot, spec.BinaryPath)
	if err != nil {
		return nil, fmt.Errorf("hash release binary: %w", err)
	}

	// 2. Bounded, non-symlink reads of all evidence artifacts.
	sbomBytes, err := readInputFileBounded(spec.WorkspaceRoot, spec.SBOMPath, MaxEntryBytes)
	if err != nil {
		return nil, fmt.Errorf("read SBOM: %w", err)
	}
	vexBytes, err := readInputFileBounded(spec.WorkspaceRoot, spec.VEXDSSEPath, MaxEntryBytes)
	if err != nil {
		return nil, fmt.Errorf("read VEX: %w", err)
	}
	slsaBytes, err := readInputFileBounded(spec.WorkspaceRoot, spec.SLSAIntotoPath, MaxEntryBytes)
	if err != nil {
		return nil, fmt.Errorf("read SLSA provenance: %w", err)
	}

	var riskBytes []byte
	if strings.TrimSpace(spec.RiskConfigPath) != "" {
		riskBytes, err = readInputFileBounded(spec.WorkspaceRoot, spec.RiskConfigPath, MaxEntryBytes)
		if err != nil {
			return nil, fmt.Errorf("read risk config: %w", err)
		}
	}

	var aibomBytes []byte
	if strings.TrimSpace(spec.AIBOMPath) != "" {
		aibomBytes, err = readInputFileBounded(spec.WorkspaceRoot, spec.AIBOMPath, MaxEntryBytes)
		if err != nil {
			return nil, fmt.Errorf("read AI-BOM config: %w", err)
		}
	}

	// 3. Validate CycloneDX SBOM JSON structure.
	if err := validateCycloneDXJSON(sbomBytes); err != nil {
		return nil, err
	}

	// 4. Verify VEX DSSE signature & exact subject SHA-256 match.
	vexPayloadForScan, err := verifyVEXArtifact(vexBytes, spec.VEXPublicKey, binarySHA256, spec.AllowUnsignedLocal)
	if err != nil {
		return nil, err
	}

	// 5. Verify Soulcaster SLSA .intoto.jsonl DSSE signature & exact subject SHA-256 match.
	slsaPub := spec.SLSAPublicKey
	if len(slsaPub) == 0 {
		slsaPub = spec.VEXPublicKey
	}
	slsaPayloadForScan, err := verifySLSAArtifact(slsaBytes, slsaPub, binarySHA256, spec.AllowUnsignedLocal)
	if err != nil {
		return nil, err
	}

	// 6. Built-in fail-closed secret scrubbing across all bundle inputs.
	if err := ScanForSecrets(EntrySBOM, sbomBytes); err != nil {
		return nil, err
	}
	if err := ScanForSecrets(EntryVEX, vexPayloadForScan); err != nil {
		return nil, err
	}
	if err := ScanForSecrets(EntryProvenance, slsaPayloadForScan); err != nil {
		return nil, err
	}
	if len(riskBytes) > 0 {
		if err := ScanForSecrets(EntryRiskConfig, riskBytes); err != nil {
			return nil, err
		}
	}
	if len(aibomBytes) > 0 {
		if err := ScanForSecrets(EntryAIBOM, aibomBytes); err != nil {
			return nil, err
		}
	}

	// 7. Assemble normalized archive entries (stripped of absolute host paths).
	entries := map[string][]byte{
		EntrySBOM:       sbomBytes,
		EntryVEX:        vexBytes,
		EntryProvenance: slsaBytes,
	}
	if len(riskBytes) > 0 {
		entries[EntryRiskConfig] = riskBytes
	}
	if len(aibomBytes) > 0 {
		entries[EntryAIBOM] = aibomBytes
	}

	artifacts := make(map[string]string, len(entries))
	for name, content := range entries {
		sum := sha256.Sum256(content)
		artifacts[name] = hex.EncodeToString(sum[:])
	}

	modTime := resolveDeterministicTime(spec.SourceDateEpoch)

	standards := make([]string, len(DefaultStandards))
	copy(standards, DefaultStandards)
	deferred := make([]string, len(DefaultDeferredClauses))
	copy(deferred, DefaultDeferredClauses)

	manifest := &CRAManifest{
		SchemaVersion:   SchemaVersion,
		Standards:       standards,
		SubjectName:     filepath.Base(filepath.Clean(spec.BinaryPath)),
		SubjectSHA256:   binarySHA256,
		Artifacts:       artifacts,
		DeferredClauses: deferred,
		GeneratedAt:     modTime.Format(time.RFC3339),
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal CRA manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	entries[EntryManifest] = manifestBytes

	// 8. Write deterministic tar.gz atomically (temp file + Sync + os.Rename).
	if err := writeDeterministicTarGzAtomic(spec.OutputTarGz, entries, modTime); err != nil {
		return nil, err
	}

	return manifest, nil
}

// VerifyCRABundle verifies an offline CRA evidence bundle against a trusted Ed25519 public key.
// It enforces bounded reads (32 MiB/entry, 128 MiB total), anti-tar-slip path safety, manifest
// SHA-256 integrity, DSSE signatures, and exact subject-digest consistency.
func VerifyCRABundle(bundlePath string, pubKey ed25519.PublicKey) (*VerifyResult, error) {
	return VerifyCRABundleWithOptions(bundlePath, VerifyOptions{
		VEXPublicKey:  pubKey,
		SLSAPublicKey: pubKey,
	})
}

// VerifyCRABundleWithOptions verifies an offline CRA evidence bundle with explicit verification options.
func VerifyCRABundleWithOptions(bundlePath string, opts VerifyOptions) (*VerifyResult, error) {
	if strings.TrimSpace(bundlePath) == "" {
		return nil, errors.New("bundlePath cannot be empty")
	}

	cleaned := filepath.Clean(bundlePath)
	fi, err := os.Lstat(cleaned)
	if err != nil {
		return nil, fmt.Errorf("stat CRA bundle %q: %w", cleaned, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: refusing to verify symlink bundle %q", ErrSymlinkViolation, cleaned)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: bundle %q is not a regular file", ErrArchiveViolation, cleaned)
	}
	if fi.Size() > MaxArchiveBytes {
		return nil, fmt.Errorf("%w: compressed bundle exceeds %d bytes", ErrArchiveViolation, MaxArchiveBytes)
	}

	f, err := os.Open(cleaned)
	if err != nil {
		return nil, fmt.Errorf("open CRA bundle %q: %w", cleaned, err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(io.LimitReader(f, MaxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid gzip archive: %v", ErrArchiveViolation, err)
	}
	defer gzr.Close()

	// Bound total decompressed stream to MaxArchiveBytes + 1 to detect gzip/tar bombs.
	limitedStream := &countingLimitReader{r: gzr, limit: MaxArchiveBytes}
	tr := tar.NewReader(limitedStream)

	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if errors.Is(err, ErrArchiveViolation) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: reading tar header: %v", ErrArchiveViolation, err)
		}

		if err := validateTarHeader(hdr); err != nil {
			return nil, err
		}
		if _, dup := files[hdr.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate tar entry %q", ErrArchiveViolation, hdr.Name)
		}

		data, err := io.ReadAll(io.LimitReader(tr, MaxEntryBytes+1))
		if err != nil {
			if errors.Is(err, ErrArchiveViolation) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: reading tar entry %q: %v", ErrArchiveViolation, hdr.Name, err)
		}
		if int64(len(data)) > MaxEntryBytes {
			return nil, fmt.Errorf("%w: entry %q exceeds maximum entry size (%d bytes)", ErrArchiveViolation, hdr.Name, MaxEntryBytes)
		}
		files[hdr.Name] = data
	}

	// Verify required core files exist.
	for _, req := range []string{EntryManifest, EntrySBOM, EntryVEX, EntryProvenance} {
		if _, ok := files[req]; !ok {
			return nil, fmt.Errorf("%w: missing required entry %q", ErrArchiveViolation, req)
		}
	}

	// Parse and validate manifest.json.
	var manifest CRAManifest
	if err := json.Unmarshal(files[EntryManifest], &manifest); err != nil {
		return nil, fmt.Errorf("%w: invalid manifest.json: %v", ErrArchiveViolation, err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported manifest schema_version %q (want %q)", ErrArchiveViolation, manifest.SchemaVersion, SchemaVersion)
	}
	if !isValidSHA256Hex(strings.ToLower(strings.TrimSpace(manifest.SubjectSHA256))) {
		return nil, fmt.Errorf("%w: invalid manifest subject_sha256", ErrDigestMismatch)
	}
	if manifest.SubjectName == "" || strings.ContainsAny(manifest.SubjectName, "/\\") || manifest.SubjectName == "." || manifest.SubjectName == ".." {
		return nil, fmt.Errorf("%w: invalid manifest subject_name %q", ErrArchiveViolation, manifest.SubjectName)
	}

	// Check every non-manifest entry is listed in manifest.Artifacts and matches SHA-256.
	for name, content := range files {
		if name == EntryManifest {
			continue
		}
		expectedHash, ok := manifest.Artifacts[name]
		if !ok {
			return nil, fmt.Errorf("%w: unattested file %q present in archive", ErrArchiveViolation, name)
		}
		sum := sha256.Sum256(content)
		actualHash := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(actualHash), []byte(strings.ToLower(strings.TrimSpace(expectedHash)))) != 1 {
			return nil, fmt.Errorf("%w: manifest SHA-256 mismatch for %q", ErrDigestMismatch, name)
		}
	}
	// Check every manifest artifact actually exists in archive.
	for name := range manifest.Artifacts {
		if _, ok := files[name]; !ok {
			return nil, fmt.Errorf("%w: manifest artifact %q missing from archive", ErrArchiveViolation, name)
		}
	}

	subjectSHA := strings.ToLower(strings.TrimSpace(manifest.SubjectSHA256))

	// If ExpectedBinaryPath was supplied, verify it matches manifest.SubjectSHA256.
	if strings.TrimSpace(opts.ExpectedBinaryPath) != "" {
		binSHA, err := vex.HashFileSHA256(opts.ExpectedBinaryPath)
		if err != nil {
			return nil, fmt.Errorf("hash expected binary: %w", err)
		}
		if subtle.ConstantTimeCompare([]byte(binSHA), []byte(subjectSHA)) != 1 {
			return nil, fmt.Errorf("%w: binary SHA-256 %s != manifest subject SHA-256 %s", ErrDigestMismatch, binSHA, subjectSHA)
		}
	}

	// Validate SBOM JSON.
	if err := validateCycloneDXJSON(files[EntrySBOM]); err != nil {
		return nil, err
	}

	// Verify VEX DSSE + subject digest consistency.
	vexPayload, err := verifyVEXArtifact(files[EntryVEX], opts.VEXPublicKey, subjectSHA, opts.AllowUnsignedLocal)
	if err != nil {
		return nil, err
	}

	// Verify SLSA provenance DSSE + subject digest consistency.
	slsaPub := opts.SLSAPublicKey
	if len(slsaPub) == 0 {
		slsaPub = opts.VEXPublicKey
	}
	slsaPayload, err := verifySLSAArtifact(files[EntryProvenance], slsaPub, subjectSHA, opts.AllowUnsignedLocal)
	if err != nil {
		return nil, err
	}

	// Scrub all artifacts for accidentally leaked secrets.
	if err := ScanForSecrets(EntrySBOM, files[EntrySBOM]); err != nil {
		return nil, err
	}
	if err := ScanForSecrets(EntryVEX, vexPayload); err != nil {
		return nil, err
	}
	if err := ScanForSecrets(EntryProvenance, slsaPayload); err != nil {
		return nil, err
	}
	if riskData, ok := files[EntryRiskConfig]; ok {
		if err := ScanForSecrets(EntryRiskConfig, riskData); err != nil {
			return nil, err
		}
	}
	if aibomData, ok := files[EntryAIBOM]; ok {
		if err := ScanForSecrets(EntryAIBOM, aibomData); err != nil {
			return nil, err
		}
	}

	return &VerifyResult{
		Manifest:      &manifest,
		ArtifactCount: len(manifest.Artifacts),
		VerifiedVEX:   !opts.AllowUnsignedLocal || len(opts.VEXPublicKey) > 0,
		VerifiedSLSA:  !opts.AllowUnsignedLocal || len(slsaPub) > 0,
	}, nil
}

func verifyVEXArtifact(vexBytes []byte, pubKey ed25519.PublicKey, expectedSHA256 string, allowUnsigned bool) ([]byte, error) {
	if !allowUnsigned || len(pubKey) > 0 {
		stmt, err := vex.VerifySignedOpenVEX(vexBytes, pubKey, expectedSHA256)
		if err != nil {
			if errors.Is(err, vex.ErrSubjectDigestMismatch) {
				return nil, fmt.Errorf("%w: %v", ErrDigestMismatch, err)
			}
			if errors.Is(err, vex.ErrDSSEInvalidSignature) {
				return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
			}
			return nil, err
		}
		payload, err := json.Marshal(stmt)
		if err != nil {
			return nil, err
		}
		return payload, nil
	}

	stmt, payload, err := vex.ParseUnverifiedDSSEVEX(vexBytes)
	if err != nil {
		return nil, fmt.Errorf("parse unsigned VEX: %w", err)
	}
	if err := vex.VerifyVEXSubjectDigest(stmt, expectedSHA256); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDigestMismatch, err)
	}
	return payload, nil
}

func verifySLSAArtifact(slsaBytes []byte, pubKey ed25519.PublicKey, expectedSHA256 string, allowUnsigned bool) ([]byte, error) {
	line := firstNonEmptyLine(slsaBytes)
	if len(line) == 0 {
		return nil, errors.New("SLSA provenance file is empty")
	}

	var env vex.DSSEEnvelope
	isDSSE := json.Unmarshal(line, &env) == nil && env.PayloadType != ""

	var payloadBytes []byte
	if isDSSE {
		if env.PayloadType != vex.DSSEPayloadTypeInToto {
			return nil, fmt.Errorf("%w: unexpected SLSA DSSE payloadType %q", ErrSignatureInvalid, env.PayloadType)
		}
		if env.Payload == "" {
			return nil, fmt.Errorf("%w: empty SLSA DSSE payload", ErrSignatureInvalid)
		}
		decoded, err := decodeBase64Flexible(env.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: decode SLSA DSSE payload: %v", ErrSignatureInvalid, err)
		}
		if len(decoded) > MaxEntryBytes {
			return nil, fmt.Errorf("%w: decoded SLSA payload exceeds %d bytes", ErrArchiveViolation, MaxEntryBytes)
		}

		if !allowUnsigned || len(pubKey) > 0 {
			if len(pubKey) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("%w: valid Ed25519 public key required to verify SLSA provenance", ErrSignatureInvalid)
			}
			if len(env.Signatures) == 0 {
				return nil, fmt.Errorf("%w: SLSA DSSE envelope contains zero signatures", ErrSignatureInvalid)
			}
			pae := vex.ComputePAE(env.PayloadType, decoded)
			verified := false
			for _, s := range env.Signatures {
				sig, err := decodeBase64Flexible(s.Sig)
				if err != nil || len(sig) != ed25519.SignatureSize {
					continue
				}
				if ed25519.Verify(pubKey, pae, sig) {
					verified = true
					break
				}
			}
			if !verified {
				return nil, fmt.Errorf("%w: SLSA DSSE signature invalid", ErrSignatureInvalid)
			}
		}
		payloadBytes = decoded
	} else {
		if !allowUnsigned {
			return nil, fmt.Errorf("%w: unsigned SLSA provenance rejected (use --allow-unsigned-local for local dry-run)", ErrSignatureInvalid)
		}
		payloadBytes = line
	}

	var stmt genericInTotoStatement
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		return nil, fmt.Errorf("parse SLSA in-toto statement: %w", err)
	}
	if stmt.Type != vex.InTotoStatementTypeV1 {
		return nil, fmt.Errorf("invalid SLSA statement _type %q (want %q)", stmt.Type, vex.InTotoStatementTypeV1)
	}
	if stmt.PredicateType != SLSAPredicateTypeV1 {
		return nil, fmt.Errorf("invalid SLSA predicateType %q (want %q)", stmt.PredicateType, SLSAPredicateTypeV1)
	}
	if len(stmt.Subject) == 0 {
		return nil, fmt.Errorf("%w: SLSA statement has empty subject list", ErrDigestMismatch)
	}

	matched := false
	for _, s := range stmt.Subject {
		actual := strings.ToLower(strings.TrimSpace(s.Digest["sha256"]))
		if isValidSHA256Hex(actual) && subtle.ConstantTimeCompare([]byte(actual), []byte(expectedSHA256)) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("%w: SLSA provenance subject SHA-256 does not match binary digest %s", ErrDigestMismatch, expectedSHA256)
	}

	return payloadBytes, nil
}

func validateCycloneDXJSON(data []byte) error {
	if len(data) == 0 {
		return errors.New("SBOM JSON is empty")
	}
	bom := cdx.NewBOM()
	decoder := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return fmt.Errorf("invalid CycloneDX SBOM JSON: %w", err)
	}
	if bom.BOMFormat != "" && bom.BOMFormat != "CycloneDX" {
		return fmt.Errorf("unexpected bomFormat %q (want CycloneDX)", bom.BOMFormat)
	}
	return nil
}

func validateTarHeader(hdr *tar.Header) error {
	if hdr.Typeflag != tar.TypeReg {
		return fmt.Errorf("%w: non-regular tar entry %q (type %d) rejected", ErrArchiveViolation, hdr.Name, hdr.Typeflag)
	}
	if hdr.Size < 0 || hdr.Size > MaxEntryBytes {
		return fmt.Errorf("%w: tar entry %q size %d out of bounds", ErrArchiveViolation, hdr.Name, hdr.Size)
	}
	name := hdr.Name
	if name == "" || strings.ContainsRune(name, '\x00') {
		return fmt.Errorf("%w: empty or null-containing tar entry name", ErrArchiveViolation)
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") || filepath.IsAbs(name) {
		return fmt.Errorf("%w: absolute tar entry path %q rejected", ErrArchiveViolation, name)
	}
	if strings.Contains(name, "\\") {
		return fmt.Errorf("%w: backslash in tar entry path %q rejected", ErrArchiveViolation, name)
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("%w: nested path %q not permitted in flat CRA bundle", ErrArchiveViolation, name)
	}
	cleaned := path.Clean(name)
	if cleaned != name || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("%w: tar-slip traversal path %q rejected", ErrArchiveViolation, name)
	}
	return nil
}

func writeDeterministicTarGzAtomic(outputPath string, entries map[string][]byte, modTime time.Time) error {
	cleaned := filepath.Clean(outputPath)
	dir := filepath.Dir(cleaned)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create output directory %q: %w", dir, err)
		}
	}

	// Re-check symlink traversal after MkdirAll to defend against TOCTOU swaps.
	if err := verifyNoSymlinkTraversal(cleaned); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, ".bomhound-cra-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary bundle file: %w", err)
	}
	tmpName := tmpFile.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	gzw, err := gzip.NewWriterLevel(tmpFile, gzip.DefaultCompression)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("create gzip writer: %w", err)
	}
	gzw.Header.ModTime = modTime
	gzw.Header.OS = 255
	gzw.Header.Name = ""

	tw := tar.NewWriter(gzw)

	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		data := entries[name]
		hdr := &tar.Header{
			Name:     name,
			Mode:     0644,
			Uid:      0,
			Gid:      0,
			Uname:    "",
			Gname:    "",
			Size:     int64(len(data)),
			ModTime:  modTime,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gzw.Close()
			_ = tmpFile.Close()
			return fmt.Errorf("write tar header %q: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			_ = tw.Close()
			_ = gzw.Close()
			_ = tmpFile.Close()
			return fmt.Errorf("write tar payload %q: %w", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		_ = gzw.Close()
		_ = tmpFile.Close()
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gzw.Close(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("close gzip writer: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temporary bundle: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temporary bundle: %w", err)
	}

	if fi, err := os.Lstat(cleaned); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: refusing to overwrite symlink %q", ErrSymlinkViolation, cleaned)
	}

	if err := os.Rename(tmpName, cleaned); err != nil {
		return fmt.Errorf("atomic rename bundle to %q: %w", cleaned, err)
	}
	renamed = true
	return nil
}

func resolveDeterministicTime(override *int64) time.Time {
	if override != nil {
		return time.Unix(*override, 0).UTC()
	}
	if raw := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH")); raw != "" {
		if sec, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return time.Unix(sec, 0).UTC()
		}
	}
	return time.Unix(0, 0).UTC()
}

func openInputFileConfined(workspaceRoot, filePath string) (*os.File, func(), error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, nil, errors.New("input file path cannot be empty")
	}

	if strings.TrimSpace(workspaceRoot) != "" {
		rootAbs, err := filepath.Abs(workspaceRoot)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve workspace root: %w", err)
		}
		var rel string
		if filepath.IsAbs(filePath) {
			rel, err = filepath.Rel(rootAbs, filepath.Clean(filePath))
			if err != nil {
				return nil, nil, fmt.Errorf("%w: %v", ErrSymlinkViolation, err)
			}
		} else {
			rel = filepath.Clean(filePath)
		}
		if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return nil, nil, fmt.Errorf("%w: path %q escapes workspace root %q", ErrSymlinkViolation, filePath, workspaceRoot)
		}

		root, err := os.OpenRoot(rootAbs)
		if err != nil {
			return nil, nil, fmt.Errorf("open confined workspace root: %w", err)
		}

		// Verify no segment inside workspaceRoot is a symlink.
		parts := strings.Split(filepath.ToSlash(rel), "/")
		cur := ""
		for _, p := range parts {
			if p == "" || p == "." {
				continue
			}
			if cur == "" {
				cur = p
			} else {
				cur = cur + "/" + p
			}
			fi, err := root.Lstat(cur)
			if err != nil {
				_ = root.Close()
				return nil, nil, fmt.Errorf("lstat %q: %w", cur, err)
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				_ = root.Close()
				return nil, nil, fmt.Errorf("%w: symlink %q rejected inside workspace root", ErrSymlinkViolation, cur)
			}
		}

		fi, err := root.Lstat(rel)
		if err != nil {
			_ = root.Close()
			return nil, nil, err
		}
		if !fi.Mode().IsRegular() {
			_ = root.Close()
			return nil, nil, fmt.Errorf("input %q is not a regular file", rel)
		}
		f, err := root.Open(rel)
		if err != nil {
			_ = root.Close()
			return nil, nil, err
		}
		return f, func() {
			_ = f.Close()
			_ = root.Close()
		}, nil
	}

	cleaned := filepath.Clean(filePath)
	if err := verifyNoSymlinkTraversal(cleaned); err != nil {
		return nil, nil, err
	}
	fi, err := os.Lstat(cleaned)
	if err != nil {
		return nil, nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%w: refusing to read symlink %q", ErrSymlinkViolation, cleaned)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("input %q is not a regular file", cleaned)
	}

	// Open via os.OpenRoot on parent directory for O_NOFOLLOW confinement on the leaf.
	dir := filepath.Dir(cleaned)
	base := filepath.Base(cleaned)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("open root %q: %w", dir, err)
	}
	lfi, err := root.Lstat(base)
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	if lfi.Mode()&os.ModeSymlink != 0 {
		_ = root.Close()
		return nil, nil, fmt.Errorf("%w: refusing to read symlink %q", ErrSymlinkViolation, cleaned)
	}
	f, err := root.Open(base)
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	return f, func() {
		_ = f.Close()
		_ = root.Close()
	}, nil
}

func hashInputFile(workspaceRoot, filePath string) (string, error) {
	f, cleanup, err := openInputFileConfined(workspaceRoot, filePath)
	if err != nil {
		return "", err
	}
	defer cleanup()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readInputFileBounded(workspaceRoot, filePath string, maxBytes int64) ([]byte, error) {
	f, cleanup, err := openInputFileConfined(workspaceRoot, filePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if fi, err := f.Stat(); err == nil && fi.Size() > maxBytes {
		return nil, fmt.Errorf("%w: file %q exceeds %d bytes", ErrArchiveViolation, filepath.Base(filePath), maxBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: file %q exceeds %d bytes", ErrArchiveViolation, filepath.Base(filePath), maxBytes)
	}
	return data, nil
}

func validateOutputPath(workspaceRoot, outputPath string) error {
	if strings.ContainsRune(outputPath, '\x00') {
		return fmt.Errorf("%w: null byte in output path", ErrSymlinkViolation)
	}
	// Reject raw '..' traversal components.
	for _, seg := range strings.Split(strings.ReplaceAll(outputPath, "\\", "/"), "/") {
		if seg == ".." {
			return fmt.Errorf("%w: parent traversal '..' rejected in output path %q", ErrSymlinkViolation, outputPath)
		}
	}

	cleaned := filepath.Clean(outputPath)
	if strings.TrimSpace(workspaceRoot) != "" {
		rootAbs, err := filepath.Abs(workspaceRoot)
		if err != nil {
			return fmt.Errorf("resolve workspace root: %w", err)
		}
		outAbs := cleaned
		if !filepath.IsAbs(outAbs) {
			outAbs = filepath.Join(rootAbs, cleaned)
		}
		rel, err := filepath.Rel(rootAbs, outAbs)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%w: output path %q escapes workspace root %q", ErrSymlinkViolation, outputPath, workspaceRoot)
		}
	}

	return verifyNoSymlinkTraversal(cleaned)
}

func verifyNoSymlinkTraversal(targetPath string) error {
	cleaned := filepath.Clean(targetPath)

	if fi, err := os.Lstat(cleaned); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symlink at %q", ErrSymlinkViolation, targetPath)
	}

	if !filepath.IsAbs(cleaned) {
		parts := strings.Split(cleaned, string(filepath.Separator))
		cur := ""
		for _, p := range parts {
			if p == "" || p == "." {
				continue
			}
			if cur == "" {
				cur = p
			} else {
				cur = cur + string(filepath.Separator) + p
			}
			if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: symlink component %q", ErrSymlinkViolation, cur)
			}
		}
		return nil
	}

	// For absolute paths, inspect every component past Darwin root symlinks (/var, /tmp, /etc).
	relToRoot := strings.TrimPrefix(cleaned, string(filepath.Separator))
	segs := strings.Split(relToRoot, string(filepath.Separator))
	cur := string(filepath.Separator)
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		cur = filepath.Join(cur, seg)
		if i == 0 && (seg == "var" || seg == "tmp" || seg == "etc") {
			continue
		}
		if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink component %q", ErrSymlinkViolation, cur)
		}
	}
	return nil
}

type countingLimitReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (c *countingLimitReader) Read(p []byte) (int, error) {
	if c.read >= c.limit {
		var probe [1]byte
		n, err := c.r.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("%w: decompressed archive exceeds maximum size (%d bytes)", ErrArchiveViolation, c.limit)
		}
		return 0, err
	}
	rem := c.limit - c.read
	if int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	return n, err
}

func firstNonEmptyLine(data []byte) []byte {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), int(MaxEntryBytes)+1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) > 0 {
			out := make([]byte, len(line))
			copy(out, line)
			return out
		}
	}
	return bytes.TrimSpace(data)
}

func decodeBase64Flexible(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func isValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
