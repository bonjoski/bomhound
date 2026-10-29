package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// DefaultLocksmithKey is the default key name in the user's Locksmith vault.
	DefaultLocksmithKey = "GH-Read"
)

var (
	// ErrNoTokenFound is returned when no token could be discovered via Locksmith.
	ErrNoTokenFound = errors.New("GitHub token not found. Please ensure your token is stored in Locksmith ('locksmith add GH-Read') or provide it via --token-stdin")
	// ErrLocksmithNotFound is returned when the locksmith CLI is not installed in PATH.
	ErrLocksmithNotFound = errors.New("locksmith binary not found in PATH: please install locksmith (brew install bonjoski/tap/locksmith)")
)

// TokenOptions configures token discovery.
type TokenOptions struct {
	LocksmithKey string
	TokenStdin   bool
}

// Internal hooks for testing and mocking external commands
var (
	execCommand = exec.CommandContext
	lookPath    = exec.LookPath
)

// GetGitHubToken retrieves the GitHub token using hardware-backed Locksmith CLI.
// Environment variables are intentionally bypassed to prevent process-table, fork, and CI leak vectors.
func GetGitHubToken(ctx context.Context, opts ...TokenOptions) (string, error) {
	key := DefaultLocksmithKey
	var readStdin bool
	if len(opts) > 0 {
		if opts[0].LocksmithKey != "" {
			key = opts[0].LocksmithKey
		}
		readStdin = opts[0].TokenStdin
	}

	// 1. Check if token requested via standard input
	if readStdin {
		var tokenBuilder strings.Builder
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				tokenBuilder.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		token := strings.TrimSpace(tokenBuilder.String())
		if token != "" {
			return token, nil
		}
	}

	// 2. Primary: Hardware-bound Locksmith vault checkout via CLI
	token, err := getFromLocksmith(ctx, key)
	if err == nil && token != "" {
		return token, nil
	}

	// 3. Fallback: Check gh CLI auth token if locksmith is not found
	if errors.Is(err, ErrLocksmithNotFound) {
		if ghToken, ghErr := getFromGH(ctx); ghErr == nil && ghToken != "" {
			return ghToken, nil
		}
	}

	if err != nil && !errors.Is(err, ErrLocksmithNotFound) {
		return "", fmt.Errorf("locksmith retrieval failed for key %q: %w", key, err)
	}

	return "", ErrNoTokenFound
}

func getFromLocksmith(ctx context.Context, key string) (string, error) {
	path, err := lookPath("locksmith")
	if err != nil {
		return "", ErrLocksmithNotFound
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := execCommand(timeoutCtx, path, "get", key, "-n")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("locksmith execution error: %w", err)
	}

	val := strings.TrimSpace(string(out))
	if val == "" || strings.HasPrefix(val, "Error:") || strings.Contains(val, "Secret not found") {
		return "", fmt.Errorf("secret %q not found in locksmith vault", key)
	}

	return val, nil
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
