package auth

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestAdversarial_CommandInjectionInKey verifies that shell metacharacters and command injection
// payloads in LocksmithKey are passed verbatim as single arguments and cannot spawn subshells.
func TestAdversarial_CommandInjectionInKey(t *testing.T) {
	defer resetHooks()

	maliciousKeys := []string{
		"key; rm -rf /",
		"key && echo pwned",
		"`id`",
		"$(whoami)",
		"key | cat /etc/passwd",
		"key\n--malicious-flag",
	}

	lookPath = func(file string) (string, error) {
		return "/usr/local/bin/locksmith", nil
	}

	for _, malKey := range maliciousKeys {
		var capturedArgs []string
		execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			capturedArgs = args
			cs := []string{"-test.run=TestHelperProcess", "--", "locksmith"}
			cmd := exec.Command(os.Args[0], cs...)
			cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "MOCK_TOKEN=mock_token"}
			return cmd
		}

		_, err := GetGitHubToken(context.Background(), TokenOptions{LocksmithKey: malKey})
		if err != nil {
			t.Fatalf("key %q failed unexpectedly: %v", malKey, err)
		}
		// In execCommand, args are ["get", key, "-n"]
		if len(capturedArgs) != 3 {
			t.Fatalf("argument count mismatch: expected 3 args, got %d: %v", len(capturedArgs), capturedArgs)
		}
		if capturedArgs[1] != malKey {
			t.Fatalf("argument was altered or split: expected %q, got %q", malKey, capturedArgs[1])
		}
	}
}

// TestAdversarial_ContextCancellationHangs verifies that a hanging locksmith execution
// (e.g. waiting indefinitely on biometric prompt or locked keychain) respects context timeouts.
func TestAdversarial_ContextCancellationHangs(t *testing.T) {
	defer resetHooks()

	lookPath = func(file string) (string, error) {
		return "/usr/local/bin/locksmith", nil
	}

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcessHang", "--"}
		cmd := exec.CommandContext(ctx, os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS_HANG=1"}
		return cmd
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := GetGitHubToken(ctx, TokenOptions{LocksmithKey: "hanging-key"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error due to timeout, got nil")
	}
	if elapsed > 1*time.Second {
		t.Fatalf("locksmith hung for too long: %v", elapsed)
	}
}

// TestAdversarial_TokenStdin_EmptyAndWhitespace ensures that whitespace-only or empty stdin
// does not return an invalid token or crash.
func TestAdversarial_TokenStdin_EmptyAndWhitespace(t *testing.T) {
	defer resetHooks()

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Mock stdin with whitespace
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdin = r
	go func() {
		w.WriteString("   \n\t\r\n   ")
		w.Close()
	}()

	// When stdin is empty/whitespace, it should fallback to locksmith key check
	_, err = GetGitHubToken(context.Background(), TokenOptions{TokenStdin: true, LocksmithKey: ""})
	if !errors.Is(err, ErrNoLocksmithKeyConfigured) {
		t.Fatalf("expected ErrNoLocksmithKeyConfigured on blank stdin, got: %v", err)
	}
}

// TestAdversarial_TokenStdin_OversizedInput ensures that large stdin inputs are properly consumed
// without buffer overflows or unbounded memory allocation.
func TestAdversarial_TokenStdin_OversizedInput(t *testing.T) {
	defer resetHooks()

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdin = r

	expectedToken := "ghp_" + strings.Repeat("A", 10000)
	go func() {
		io.WriteString(w, expectedToken+"\n")
		w.Close()
	}()

	token, err := GetGitHubToken(context.Background(), TokenOptions{TokenStdin: true})
	if err != nil {
		t.Fatalf("unexpected error reading oversized token: %v", err)
	}
	if token != expectedToken {
		t.Fatalf("token mismatch: length got %d, expected %d", len(token), len(expectedToken))
	}
}

// TestHelperProcessHang is used by TestAdversarial_ContextCancellationHangs
func TestHelperProcessHang(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_HANG") != "1" {
		return
	}
	time.Sleep(5 * time.Second)
	os.Exit(0)
}
