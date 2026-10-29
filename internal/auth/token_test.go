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

func TestGetGitHubToken_GitHubTokenEnv(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "ghp_from_github_token")
	t.Setenv("GH_TOKEN", "")

	token, err := GetGitHubToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "ghp_from_github_token" {
		t.Fatalf("expected ghp_from_github_token, got: %s", token)
	}
}

func TestGetGitHubToken_GHTokenEnv(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "ghp_from_gh_token")

	token, err := GetGitHubToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "ghp_from_gh_token" {
		t.Fatalf("expected ghp_from_gh_token, got: %s", token)
	}
}

func TestGetGitHubToken_EnvPrecedence(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "ghp_primary")
	t.Setenv("GH_TOKEN", "ghp_secondary")

	token, err := GetGitHubToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "ghp_primary" {
		t.Fatalf("expected ghp_primary, got: %s", token)
	}
}

func TestGetGitHubToken_LocksmithProvider(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	lookPath = func(file string) (string, error) {
		if file == "locksmith" {
			return "/usr/local/bin/locksmith", nil
		}
		return "", errors.New("not found")
	}

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Mock exec helper by echoing expected token
		cs := []string{"-test.run=TestHelperProcess", "--", "locksmith", args[1]}
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1", "MOCK_TOKEN=ghp_from_locksmith_vault"}
		return cmd
	}

	token, err := GetGitHubToken(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "ghp_from_locksmith_vault" {
		t.Fatalf("expected ghp_from_locksmith_vault, got: %s", token)
	}
}

func TestGetGitHubToken_GHCLIFallback(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

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

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

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
