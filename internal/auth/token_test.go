package auth

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func resetHooks() {
	lookPath = exec.LookPath
	execCommand = exec.CommandContext
}

func TestGetGitHubToken_LocksmithExplicitKey(t *testing.T) {
	defer resetHooks()

	// Ensure environment variables are NOT used
	t.Setenv("GITHUB_TOKEN", "should_be_ignored")
	t.Setenv("GH_TOKEN", "should_be_ignored")

	var invokedKey string
	lookPath = func(file string) (string, error) {
		if file == "locksmith" {
			return "/opt/homebrew/bin/locksmith", nil
		}
		return "", errors.New("not found")
	}

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		invokedKey = args[1] // locksmith get <key> -n
		cs := []string{"-test.run=TestHelperProcess", "--", "locksmith"}
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "MOCK_TOKEN=gho_from_locksmith_configured_key"}
		return cmd
	}

	token, err := GetGitHubToken(context.Background(), TokenOptions{LocksmithKey: "my-vault-key"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "gho_from_locksmith_configured_key" {
		t.Fatalf("expected gho_from_locksmith_configured_key, got: %s", token)
	}
	if invokedKey != "my-vault-key" {
		t.Fatalf("expected key my-vault-key, got: %s", invokedKey)
	}
}

func TestGetGitHubToken_NoKeyConfigured(t *testing.T) {
	defer resetHooks()

	_, err := GetGitHubToken(context.Background(), TokenOptions{LocksmithKey: ""})
	if !errors.Is(err, ErrNoLocksmithKeyConfigured) {
		t.Fatalf("expected ErrNoLocksmithKeyConfigured, got: %v", err)
	}
}

func TestGetGitHubToken_LocksmithNotFound(t *testing.T) {
	defer resetHooks()

	lookPath = func(file string) (string, error) {
		return "", errors.New("command not found")
	}

	_, err := GetGitHubToken(context.Background(), TokenOptions{LocksmithKey: "my-key"})
	if !errors.Is(err, ErrLocksmithNotFound) {
		t.Fatalf("expected ErrLocksmithNotFound, got: %v", err)
	}
}

// TestHelperProcess is used to mock external CLI processes (locksmith) in tests
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	token := os.Getenv("MOCK_TOKEN")
	if token != "" {
		os.Stdout.WriteString(token + "\n")
		os.Exit(0)
	}
	os.Exit(1)
}
