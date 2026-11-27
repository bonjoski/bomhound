package vex

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndVerifyOpenVEX_LocalKeyAndEphemeral(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "myapp")
	if err := os.WriteFile(binPath, []byte("deterministic-release-binary-v1"), 0600); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	expectedSHA, err := HashFileSHA256(binPath)
	if err != nil {
		t.Fatalf("HashFileSHA256: %v", err)
	}

	doc := NewOpenVEXDocument("bomhound-test")
	doc.Statements = append(doc.Statements, Statement{
		Vulnerability: VulnerabilityIdent{Name: "CVE-2026-0001"},
		Products:      []string{"pkg:generic/myapp@1.0.0"},
		Status:        StatusNotAffected,
		Justification: JustificationVulnerableCodeNotPresent,
	})

	// 1. Offline PEM key file signing
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privPEM, err := EncodeEd25519PrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("EncodeEd25519PrivateKeyPEM: %v", err)
	}
	keyPath := filepath.Join(tmpDir, "signing.key")
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	dsseBytes, err := SignOpenVEX(doc, SignedVEXOptions{
		ArtifactPath:   binPath,
		OfflineKeyPath: keyPath,
	})
	if err != nil {
		t.Fatalf("SignOpenVEX failed: %v", err)
	}

	stmt, err := VerifySignedOpenVEX(dsseBytes, pub, expectedSHA)
	if err != nil {
		t.Fatalf("VerifySignedOpenVEX failed: %v", err)
	}
	if stmt.Type != InTotoStatementTypeV1 {
		t.Errorf("got _type=%q, want %q", stmt.Type, InTotoStatementTypeV1)
	}
	if stmt.PredicateType != OpenVEXPredicateType {
		t.Errorf("got predicateType=%q, want %q", stmt.PredicateType, OpenVEXPredicateType)
	}
	if stmt.Subject[0].Name != "myapp" {
		t.Errorf("expected basename subject 'myapp' (no host path), got %q", stmt.Subject[0].Name)
	}
	if stmt.Subject[0].Digest["sha256"] != expectedSHA {
		t.Errorf("digest mismatch: got %s, want %s", stmt.Subject[0].Digest["sha256"], expectedSHA)
	}

	// 2. Ephemeral offline keypair mode
	ephDSSE, ephPub, err := SignOpenVEXWithKey(doc, SignedVEXOptions{ArtifactPath: binPath})
	if err != nil {
		t.Fatalf("ephemeral SignOpenVEXWithKey failed: %v", err)
	}
	if _, err := VerifySignedOpenVEX(ephDSSE, ephPub, expectedSHA); err != nil {
		t.Fatalf("VerifySignedOpenVEX ephemeral failed: %v", err)
	}
}

func TestSignOpenVEX_LocksmithSocket(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "service-bin")
	if err := os.WriteFile(binPath, []byte("socket-signed-binary"), 0600); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	expectedSHA, err := HashFileSHA256(binPath)
	if err != nil {
		t.Fatalf("HashFileSHA256: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubPEM, err := EncodeEd25519PublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("EncodeEd25519PublicKeyPEM: %v", err)
	}

	sockDir, err := os.MkdirTemp("/tmp", "bh-")
	if err != nil {
		t.Fatalf("mkdirtemp for unix socket: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "l.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadBytes('\n')
		if err != nil {
			done <- err
			return
		}
		var req locksmithSignRequest
		if err := json.Unmarshal(line, &req); err != nil {
			done <- err
			return
		}
		if req.Action != "sign_dsse" {
			done <- errors.New("unexpected action: " + req.Action)
			return
		}
		pae, err := base64.StdEncoding.DecodeString(req.PAEB64)
		if err != nil {
			done <- err
			return
		}
		sig := ed25519.Sign(priv, pae)
		resp := locksmithSignResponse{
			KeyID:        KeyIDForPublicKey(pub),
			SigB64:       base64.StdEncoding.EncodeToString(sig),
			PublicKeyPEM: string(pubPEM),
		}
		out, _ := json.Marshal(resp)
		_, err = conn.Write(append(out, '\n'))
		done <- err
	}()

	doc := NewOpenVEXDocument("socket-test")
	dsseBytes, gotPub, err := SignOpenVEXWithKey(doc, SignedVEXOptions{
		ArtifactPath:    binPath,
		LocksmithSocket: sockPath,
	})
	if err != nil {
		t.Fatalf("SignOpenVEXWithKey via socket failed: %v", err)
	}
	if srvErr := <-done; srvErr != nil {
		t.Fatalf("mock locksmith server error: %v", srvErr)
	}
	if _, err := VerifySignedOpenVEX(dsseBytes, gotPub, expectedSHA); err != nil {
		t.Fatalf("VerifySignedOpenVEX failed: %v", err)
	}
}

func TestVerifySignedOpenVEX_FailClosed(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "app")
	if err := os.WriteFile(binPath, []byte("original-binary"), 0600); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	expectedSHA, _ := HashFileSHA256(binPath)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	doc := NewOpenVEXDocument("fail-closed-test")
	dsseBytes, err := SignOpenVEX(doc, SignedVEXOptions{
		ArtifactPath: binPath,
		PrivateKey:   priv,
	})
	if err != nil {
		t.Fatalf("SignOpenVEX: %v", err)
	}

	// Wrong public key
	if _, err := VerifySignedOpenVEX(dsseBytes, wrongPub, expectedSHA); !errors.Is(err, ErrDSSEInvalidSignature) {
		t.Errorf("expected ErrDSSEInvalidSignature for wrong key, got: %v", err)
	}

	// Wrong subject digest
	wrongDigest := strings.Repeat("a", 64)
	if _, err := VerifySignedOpenVEX(dsseBytes, pub, wrongDigest); !errors.Is(err, ErrSubjectDigestMismatch) {
		t.Errorf("expected ErrSubjectDigestMismatch for tampered digest, got: %v", err)
	}

	// Unsigned raw OpenVEX document
	rawVEX, _ := doc.ToJSON()
	if _, err := VerifySignedOpenVEX(rawVEX, pub, expectedSHA); !errors.Is(err, ErrDSSEInvalidSignature) {
		t.Errorf("expected ErrDSSEInvalidSignature for unsigned VEX, got: %v", err)
	}

	// Symlink artifact refused
	linkPath := filepath.Join(tmpDir, "symlink-bin")
	if err := os.Symlink(binPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := SignOpenVEX(doc, SignedVEXOptions{ArtifactPath: linkPath, PrivateKey: priv}); err == nil {
		t.Error("expected symlink artifact to be rejected fail-closed")
	}
}
