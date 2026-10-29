package auth

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	// ErrNoTokenFound is returned when no token could be discovered from environment, Locksmith, or gh CLI.
	ErrNoTokenFound = errors.New("GitHub token not found. Please provide a token via GITHUB_TOKEN environment variable, Locksmith ('locksmith add GITHUB_TOKEN'), or GitHub CLI ('gh auth login')")
)

// TokenOptions configures token discovery.
type TokenOptions struct {
	LocksmithKey string
}

// Internal hooks for testing and mocking external commands
var (
	execCommand = exec.CommandContext
	lookPath    = exec.LookPath
)

// GetGitHubToken retrieves the GitHub token using the standard resolution chain:
// 1. GITHUB_TOKEN or GH_TOKEN environment variables
// 2. Locksmith secrets vault (if installed in PATH)
// 3. GitHub CLI (`gh auth token`, if installed in PATH)
func GetGitHubToken(ctx context.Context, opts ...TokenOptions) (string, error) {
	// 1. Check environment variables (standard for CI/CD and scripts)
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		return token, nil
	}
	if token := strings.TrimSpace(os.Getenv("GH_TOKEN")); token != "" {
		return token, nil
	}

	locksmithKey := "GITHUB_TOKEN"
	if len(opts) > 0 && opts[0].LocksmithKey != "" {
		locksmithKey = opts[0].LocksmithKey
	}

	// 2. Attempt Locksmith hardware-bound secret checkout
	if token, err := getFromLocksmith(ctx, locksmithKey); err == nil && token != "" {
		return token, nil
	}

	// 3. Attempt GitHub CLI (gh auth token)
	if token, err := getFromGH(ctx); err == nil && token != "" {
		return token, nil
	}

	return "", ErrNoTokenFound
}

func getFromLocksmith(ctx context.Context, key string) (string, error) {
	path, err := lookPath("locksmith")
	if err != nil {
		return "", err
	}

	// Try primary key, then common fallbacks if default GITHUB_TOKEN
	keysToTry := []string{key}
	if key == "GITHUB_TOKEN" {
		keysToTry = []string{"GITHUB_TOKEN", "github_token", "GH_TOKEN", "GH-Read"}
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	for _, k := range keysToTry {
		cmd := execCommand(timeoutCtx, path, "get", k, "-n")
		out, err := cmd.Output()
		if err == nil {
			val := strings.TrimSpace(string(out))
			if val != "" && !strings.HasPrefix(val, "Error:") && !strings.Contains(val, "Secret not found") {
				return val, nil
			}
		}
	}

	return "", errors.New("key not found in locksmith")
}

func getFromGH(ctx context.Context) (string, error) {
	path, err := lookPath("gh")
	if err != nil {
		return "", err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	cmd := execCommand(timeoutCtx, path, "auth", "token")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	val := strings.TrimSpace(string(out))
	if val != "" {
		return val, nil
	}
	return "", errors.New("empty token from gh")
}
