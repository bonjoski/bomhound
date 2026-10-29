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

func TestGetGitHubToken_LocksmithDefaultKey(t *testing.T) {
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
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "MOCK_TOKEN=gho_from_locksmith_gh_read"}
		return cmd
	}

	token, err := GetGitHubToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "gho_from_locksmith_gh_read" {
		t.Fatalf("expected gho_from_locksmith_gh_read, got: %s", token)
	}
	if invokedKey != DefaultLocksmithKey {
		t.Fatalf("expected default key %s, got: %s", DefaultLocksmithKey, invokedKey)
	}
}

func TestGetGitHubToken_LocksmithCustomKey(t *testing.T) {
	defer resetHooks()

	var invokedKey string
	lookPath = func(file string) (string, error) {
		if file == "locksmith" {
			return "/opt/homebrew/bin/locksmith", nil
		}
		return "", errors.New("not found")
	}

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		invokedKey = args[1]
		cs := []string{"-test.run=TestHelperProcess", "--", "locksmith"}
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "MOCK_TOKEN=gho_custom_key_val"}
		return cmd
	}

	token, err := GetGitHubToken(context.Background(), TokenOptions{LocksmithKey: "MY_CUSTOM_KEY"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "gho_custom_key_val" {
		t.Fatalf("expected gho_custom_key_val, got: %s", token)
	}
	if invokedKey != "MY_CUSTOM_KEY" {
		t.Fatalf("expected key MY_CUSTOM_KEY, got: %s", invokedKey)
	}
}

func TestGetGitHubToken_GHCLIFallbackWhenNoLocksmith(t *testing.T) {
	defer resetHooks()

	lookPath = func(file string) (string, error) {
		if file == "gh" {
			return "/usr/local/bin/gh", nil
		}
		return "", errors.New("not found")
	}

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestHelperProcess", "--", "gh"}
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "MOCK_TOKEN=gho_from_gh_cli"}
		return cmd
	}

	token, err := GetGitHubToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "gho_from_gh_cli" {
		t.Fatalf("expected gho_from_gh_cli, got: %s", token)
	}
}

func TestGetGitHubToken_NoTokenFound(t *testing.T) {
	defer resetHooks()

	lookPath = func(file string) (string, error) {
		return "", errors.New("command not found")
	}

	_, err := GetGitHubToken(context.Background())
	if !errors.Is(err, ErrNoTokenFound) {
		t.Fatalf("expected ErrNoTokenFound, got: %v", err)
	}
}

// TestHelperProcess is used to mock external CLI processes (locksmith and gh) in tests
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
