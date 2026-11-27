package vex

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DSSEPayloadTypeInToto is the standard DSSE media type for in-toto statements.
	DSSEPayloadTypeInToto = "application/vnd.in-toto+json"

	// InTotoStatementTypeV1 is the in-toto v1.0 Statement _type URI.
	InTotoStatementTypeV1 = "https://in-toto.io/Statement/v1"

	// OpenVEXPredicateType is the OpenVEX v0.2.0 predicateType URI for in-toto statements.
	OpenVEXPredicateType = "https://openvex.dev/ns/v0.2.0"

	maxKeyFileBytes = 64 << 10 // 64 KiB
	maxVEXDSSEBytes = 32 << 20 // 32 MiB
	maxSocketResp   = 1 << 20  // 1 MiB
	socketTimeout   = 10 * time.Second
)

var (
	// ErrDSSEInvalidSignature indicates cryptographic verification of a DSSE envelope failed.
	ErrDSSEInvalidSignature = errors.New("DSSE Ed25519 signature verification failed")

	// ErrSubjectDigestMismatch indicates the attested subject SHA-256 does not match the expected binary digest.
	ErrSubjectDigestMismatch = errors.New("in-toto subject SHA-256 digest mismatch")
)

// DigestSet maps cryptographic hash algorithms to lowercase hex digests.
type DigestSet map[string]string

// ResourceDescriptor describes a bound in-toto subject artifact.
type ResourceDescriptor struct {
	Name   string    `json:"name"`
	Digest DigestSet `json:"digest"`
}

// InTotoVEXStatement wraps an OpenVEX v0.2.0 document in an in-toto v1.0 Statement.
type InTotoVEXStatement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     *OpenVEXDocument     `json:"predicate"`
}

// DSSESignature represents a single signature inside a DSSE v1.0 envelope.
type DSSESignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope represents a Dead Simple Signing Envelope (DSSE v1.0).
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// SignedVEXOptions configures DSSE signing for an OpenVEX document.
type SignedVEXOptions struct {
	ArtifactPath    string             // Binary whose SHA-256 binds in-toto subject[0]
	LocksmithSocket string             // Optional LOCKSMITH_SOCKET for Ed25519 DSSE signing
	OfflineKeyPath  string             // Optional local Ed25519 private key file/PEM/hex/base64
	PrivateKey      ed25519.PrivateKey // Optional in-memory Ed25519 private key
}

// ComputePAE constructs the DSSEv1 Pre-Authentication Encoding byte slice:
// "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
func ComputePAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, len(prefix)+len(payload))
	copy(out, prefix)
	copy(out[len(prefix):], payload)
	return out
}

// KeyIDForPublicKey computes a deterministic 128-bit lowercase hex key identifier for an Ed25519 public key.
func KeyIDForPublicKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// HashFileSHA256 computes the lowercase hex SHA-256 digest of a regular file, refusing symlinks.
func HashFileSHA256(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("artifact path cannot be empty")
	}
	cleaned := filepath.Clean(path)
	fi, err := os.Lstat(cleaned)
	if err != nil {
		return "", fmt.Errorf("stat artifact %q: %w", cleaned, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to hash symlink artifact %q", cleaned)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("artifact %q is not a regular file", cleaned)
	}

	f, err := os.Open(cleaned)
	if err != nil {
		return "", fmt.Errorf("open artifact %q: %w", cleaned, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash artifact %q: %w", cleaned, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SignOpenVEX wraps doc inside an in-toto v1.0 Statement whose Subject[0] binds
// exact SHA-256 of ArtifactPath, then signs the DSSE v1 envelope.
func SignOpenVEX(doc *OpenVEXDocument, opts SignedVEXOptions) ([]byte, error) {
	dsseBytes, _, err := SignOpenVEXWithKey(doc, opts)
	return dsseBytes, err
}

// SignOpenVEXWithKey performs the same DSSE signing as SignOpenVEX and also returns
// the Ed25519 public key corresponding to the signing key (useful for ephemeral offline keys).
func SignOpenVEXWithKey(doc *OpenVEXDocument, opts SignedVEXOptions) ([]byte, ed25519.PublicKey, error) {
	if doc == nil {
		return nil, nil, errors.New("cannot sign nil OpenVEX document")
	}
	if strings.TrimSpace(opts.ArtifactPath) == "" {
		return nil, nil, errors.New("ArtifactPath is required to bind OpenVEX in-toto subject")
	}

	digestHex, err := HashFileSHA256(opts.ArtifactPath)
	if err != nil {
		return nil, nil, err
	}

	stmt := &InTotoVEXStatement{
		Type: InTotoStatementTypeV1,
		Subject: []ResourceDescriptor{
			{
				Name:   filepath.Base(filepath.Clean(opts.ArtifactPath)),
				Digest: DigestSet{"sha256": digestHex},
			},
		},
		PredicateType: OpenVEXPredicateType,
		Predicate:     doc,
	}

	payloadBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal in-toto OpenVEX statement: %w", err)
	}

	pae := ComputePAE(DSSEPayloadTypeInToto, payloadBytes)

	var (
		sigBytes []byte
		keyID    string
		pubKey   ed25519.PublicKey
	)

	switch {
	case len(opts.PrivateKey) > 0:
		if len(opts.PrivateKey) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid Ed25519 private key length: got %d, want %d", len(opts.PrivateKey), ed25519.PrivateKeySize)
		}
		pubKey = opts.PrivateKey.Public().(ed25519.PublicKey)
		keyID = KeyIDForPublicKey(pubKey)
		sigBytes = ed25519.Sign(opts.PrivateKey, pae)

	case strings.TrimSpace(opts.OfflineKeyPath) != "":
		priv, err := ParseEd25519PrivateKey(opts.OfflineKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load offline Ed25519 private key: %w", err)
		}
		pubKey = priv.Public().(ed25519.PublicKey)
		keyID = KeyIDForPublicKey(pubKey)
		sigBytes = ed25519.Sign(priv, pae)

	case strings.TrimSpace(opts.LocksmithSocket) != "":
		sig, kid, pub, err := signViaLocksmithSocket(opts.LocksmithSocket, DSSEPayloadTypeInToto, payloadBytes, pae)
		if err != nil {
			return nil, nil, fmt.Errorf("sign via locksmith socket: %w", err)
		}
		sigBytes = sig
		keyID = kid
		pubKey = pub

	default:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate ephemeral Ed25519 keypair: %w", err)
		}
		pubKey = pub
		keyID = KeyIDForPublicKey(pub)
		sigBytes = ed25519.Sign(priv, pae)
	}

	env := &DSSEEnvelope{
		PayloadType: DSSEPayloadTypeInToto,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures: []DSSESignature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sigBytes),
			},
		},
	}

	envBytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal DSSE envelope: %w", err)
	}
	return append(envBytes, '\n'), pubKey, nil
}

// VerifySignedOpenVEX verifies a DSSE v1 Ed25519 envelope wrapping an in-toto v1.0 OpenVEX
// statement and enforces exact SHA-256 subject-digest binding against expectedArtifactSHA256.
func VerifySignedOpenVEX(dsseBytes []byte, pubKey ed25519.PublicKey, expectedArtifactSHA256 string) (*InTotoVEXStatement, error) {
	if len(dsseBytes) == 0 {
		return nil, fmt.Errorf("%w: empty DSSE input", ErrDSSEInvalidSignature)
	}
	if len(dsseBytes) > maxVEXDSSEBytes {
		return nil, fmt.Errorf("DSSE OpenVEX exceeds maximum allowed size (%d bytes)", maxVEXDSSEBytes)
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: valid Ed25519 public key required", ErrDSSEInvalidSignature)
	}

	expectedNorm := strings.ToLower(strings.TrimSpace(expectedArtifactSHA256))
	if !isValidSHA256Hex(expectedNorm) {
		return nil, fmt.Errorf("%w: expectedArtifactSHA256 must be a valid 64-char hex SHA-256 digest", ErrSubjectDigestMismatch)
	}

	var env DSSEEnvelope
	if err := json.Unmarshal(dsseBytes, &env); err != nil {
		return nil, fmt.Errorf("unmarshal DSSE envelope: %w", err)
	}
	if env.PayloadType == "" && len(env.Signatures) == 0 {
		return nil, fmt.Errorf("%w: unsigned OpenVEX rejected", ErrDSSEInvalidSignature)
	}
	if env.PayloadType != DSSEPayloadTypeInToto {
		return nil, fmt.Errorf("%w: unexpected payloadType %q (want %q)", ErrDSSEInvalidSignature, env.PayloadType, DSSEPayloadTypeInToto)
	}
	if env.Payload == "" {
		return nil, fmt.Errorf("%w: empty DSSE payload", ErrDSSEInvalidSignature)
	}
	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("%w: DSSE envelope contains zero signatures", ErrDSSEInvalidSignature)
	}

	payloadBytes, err := decodeBase64Flexible(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decode base64 payload: %v", ErrDSSEInvalidSignature, err)
	}
	if len(payloadBytes) > maxVEXDSSEBytes {
		return nil, fmt.Errorf("decoded OpenVEX payload exceeds maximum allowed size (%d bytes)", maxVEXDSSEBytes)
	}

	pae := ComputePAE(env.PayloadType, payloadBytes)
	verified := false
	for _, entry := range env.Signatures {
		sigBytes, err := decodeBase64Flexible(entry.Sig)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pubKey, pae, sigBytes) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrDSSEInvalidSignature
	}

	stmt, err := ParseInTotoVEXStatement(payloadBytes)
	if err != nil {
		return nil, err
	}

	if err := VerifyVEXSubjectDigest(stmt, expectedNorm); err != nil {
		return nil, err
	}
	return stmt, nil
}

// ParseInTotoVEXStatement parses and validates an in-toto v1.0 OpenVEX statement payload.
func ParseInTotoVEXStatement(payload []byte) (*InTotoVEXStatement, error) {
	if len(payload) > maxVEXDSSEBytes {
		return nil, fmt.Errorf("in-toto VEX statement exceeds maximum allowed size (%d bytes)", maxVEXDSSEBytes)
	}
	var stmt InTotoVEXStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal in-toto VEX statement: %w", err)
	}
	if stmt.Type != InTotoStatementTypeV1 {
		return nil, fmt.Errorf("invalid in-toto _type %q (want %q)", stmt.Type, InTotoStatementTypeV1)
	}
	if stmt.PredicateType != OpenVEXPredicateType {
		return nil, fmt.Errorf("invalid OpenVEX predicateType %q (want %q)", stmt.PredicateType, OpenVEXPredicateType)
	}
	if len(stmt.Subject) == 0 {
		return nil, errors.New("in-toto VEX statement has empty subject list")
	}
	if stmt.Predicate == nil {
		return nil, errors.New("in-toto VEX statement has nil OpenVEX predicate")
	}
	for i, s := range stmt.Subject {
		if strings.TrimSpace(s.Name) == "" {
			return nil, fmt.Errorf("subject[%d] name is required", i)
		}
		dig := strings.ToLower(strings.TrimSpace(s.Digest["sha256"]))
		if !isValidSHA256Hex(dig) {
			return nil, fmt.Errorf("subject[%d] %q has missing or invalid sha256 digest", i, s.Name)
		}
	}
	return &stmt, nil
}

// ParseUnverifiedDSSEVEX extracts the in-toto VEX statement from a DSSE envelope (or raw statement)
// WITHOUT verifying its cryptographic signature. Only use when explicitly permitted for local dry-runs.
func ParseUnverifiedDSSEVEX(data []byte) (*InTotoVEXStatement, []byte, error) {
	if len(data) > maxVEXDSSEBytes {
		return nil, nil, fmt.Errorf("VEX document exceeds maximum allowed size (%d bytes)", maxVEXDSSEBytes)
	}
	var env DSSEEnvelope
	if err := json.Unmarshal(data, &env); err == nil && env.PayloadType == DSSEPayloadTypeInToto && env.Payload != "" {
		payloadBytes, err := decodeBase64Flexible(env.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("decode DSSE VEX payload: %w", err)
		}
		stmt, err := ParseInTotoVEXStatement(payloadBytes)
		if err != nil {
			return nil, nil, err
		}
		return stmt, payloadBytes, nil
	}

	stmt, err := ParseInTotoVEXStatement(data)
	if err != nil {
		return nil, nil, err
	}
	return stmt, data, nil
}

// VerifyVEXSubjectDigest checks that stmt.Subject[0].Digest["sha256"] matches expectedSHA256 in constant time.
func VerifyVEXSubjectDigest(stmt *InTotoVEXStatement, expectedSHA256 string) error {
	if stmt == nil || len(stmt.Subject) == 0 {
		return fmt.Errorf("%w: missing subject", ErrSubjectDigestMismatch)
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA256))
	if !isValidSHA256Hex(expected) {
		return fmt.Errorf("%w: invalid expected sha256", ErrSubjectDigestMismatch)
	}
	actual := strings.ToLower(strings.TrimSpace(stmt.Subject[0].Digest["sha256"]))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return fmt.Errorf("%w: VEX subject digest %s != expected %s", ErrSubjectDigestMismatch, actual, expected)
	}
	return nil
}

type locksmithSignRequest struct {
	Action      string `json:"action"`
	PayloadType string `json:"payload_type"`
	PayloadB64  string `json:"payload_b64"`
	PAEB64      string `json:"pae_b64"`
}

type locksmithSignResponse struct {
	KeyID        string `json:"keyid,omitempty"`
	SigB64       string `json:"sig_b64,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	Error        string `json:"error,omitempty"`
}

func signViaLocksmithSocket(socketPath, payloadType string, payload, pae []byte) ([]byte, string, ed25519.PublicKey, error) {
	conn, err := net.DialTimeout("unix", socketPath, socketTimeout)
	if err != nil {
		return nil, "", nil, fmt.Errorf("dial unix socket %q: %w", socketPath, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(socketTimeout)); err != nil {
		return nil, "", nil, fmt.Errorf("set socket deadline: %w", err)
	}

	req := locksmithSignRequest{
		Action:      "sign_dsse",
		PayloadType: payloadType,
		PayloadB64:  base64.StdEncoding.EncodeToString(payload),
		PAEB64:      base64.StdEncoding.EncodeToString(pae),
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, "", nil, fmt.Errorf("marshal locksmith request: %w", err)
	}
	reqBytes = append(reqBytes, '\n')
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, "", nil, fmt.Errorf("write locksmith request: %w", err)
	}

	reader := bufio.NewReader(io.LimitReader(conn, maxSocketResp))
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, "", nil, fmt.Errorf("read locksmith response: %w", err)
	}
	if len(line) == 0 {
		return nil, "", nil, errors.New("empty response from locksmith socket")
	}

	var resp locksmithSignResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, "", nil, fmt.Errorf("unmarshal locksmith response: %w", err)
	}
	if resp.Error != "" {
		return nil, "", nil, fmt.Errorf("locksmith error: %s", resp.Error)
	}

	sigBytes, err := decodeBase64Flexible(resp.SigB64)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, "", nil, errors.New("invalid Ed25519 signature returned by locksmith")
	}

	var pub ed25519.PublicKey
	if strings.TrimSpace(resp.PublicKeyPEM) != "" {
		parsedPub, err := ParseEd25519PublicKey(resp.PublicKeyPEM)
		if err != nil {
			return nil, "", nil, fmt.Errorf("parse public key returned by locksmith: %w", err)
		}
		if !ed25519.Verify(parsedPub, pae, sigBytes) {
			return nil, "", nil, errors.New("locksmith returned signature failing self-verification")
		}
		pub = parsedPub
	}

	keyID := resp.KeyID
	if keyID == "" && len(pub) == ed25519.PublicKeySize {
		keyID = KeyIDForPublicKey(pub)
	}

	return sigBytes, keyID, pub, nil
}

// EncodeEd25519PublicKeyPEM encodes an Ed25519 public key into PKIX PEM format.
func EncodeEd25519PublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(pub))
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodeEd25519PrivateKeyPEM encodes an Ed25519 private key into PKCS#8 PEM format.
func EncodeEd25519PrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(priv))
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseEd25519PrivateKey loads an Ed25519 private key from a file path, PEM block, hex string, or base64 string.
func ParseEd25519PrivateKey(input string) (ed25519.PrivateKey, error) {
	raw, err := resolveKeyMaterial(input)
	if err != nil {
		return nil, err
	}

	if strings.Contains(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM block for Ed25519 private key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		edPriv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 private key is %T, expected ed25519.PrivateKey", parsed)
		}
		return edPriv, nil
	}

	decoded, err := decodeHexOrBase64(raw)
	if err != nil {
		return nil, fmt.Errorf("decode Ed25519 private key: %w", err)
	}

	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		priv := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
		if subtle.ConstantTimeCompare(priv, decoded) != 1 {
			return nil, errors.New("malformed 64-byte Ed25519 private key: public suffix mismatches seed")
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unexpected Ed25519 private key length %d (expected 32-byte seed or 64-byte private key)", len(decoded))
	}
}

// ParseEd25519PublicKey loads an Ed25519 public key from a file path, PEM block, hex string, or base64 string.
func ParseEd25519PublicKey(input string) (ed25519.PublicKey, error) {
	raw, err := resolveKeyMaterial(input)
	if err != nil {
		return nil, err
	}

	if strings.Contains(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM block for Ed25519 public key")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		edPub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PKIX public key is %T, expected ed25519.PublicKey", parsed)
		}
		return edPub, nil
	}

	decoded, err := decodeHexOrBase64(raw)
	if err != nil {
		return nil, fmt.Errorf("decode Ed25519 public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected Ed25519 public key length %d (expected 32 bytes)", len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func resolveKeyMaterial(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", errors.New("empty key material")
	}
	if !strings.Contains(trimmed, "\n") {
		if info, err := os.Lstat(trimmed); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("refusing to load key material from symlink %q", trimmed)
			}
			if !info.IsDir() {
				f, err := os.Open(trimmed)
				if err != nil {
					return "", fmt.Errorf("open key file %q: %w", trimmed, err)
				}
				defer f.Close()
				buf, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
				if err != nil {
					return "", fmt.Errorf("read key file %q: %w", trimmed, err)
				}
				if len(buf) > maxKeyFileBytes {
					return "", fmt.Errorf("key file %q exceeds %d bytes", trimmed, maxKeyFileBytes)
				}
				return strings.TrimSpace(string(buf)), nil
			}
		}
	}
	return trimmed, nil
}

func decodeHexOrBase64(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	return decodeBase64Flexible(s)
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
