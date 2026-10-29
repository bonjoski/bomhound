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

var (
	// ErrNoLocksmithKeyConfigured is returned when no key name is provided in config or flag.
	ErrNoLocksmithKeyConfigured = errors.New("locksmith key not configured: please set 'auth.locksmith_key' in your config file or pass --locksmith-key <key>")
	// ErrNoTokenFound is returned when no token could be discovered via Locksmith or stdin.
	ErrNoTokenFound = errors.New("GitHub token not found via Locksmith. Please ensure the key exists in your vault ('locksmith add <key>') or provide it via --token-stdin")
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
func GetGitHubToken(ctx context.Context, opts TokenOptions) (string, error) {
	// 1. Check if token requested via standard input
	if opts.TokenStdin {
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

	// 2. Locksmith key must be explicitly configured
	key := strings.TrimSpace(opts.LocksmithKey)
	if key == "" {
		return "", ErrNoLocksmithKeyConfigured
	}

	// 3. Primary: Hardware-bound Locksmith vault checkout via CLI
	token, err := getFromLocksmith(ctx, key)
	if err == nil && token != "" {
		return token, nil
	}

	if err != nil {
		if errors.Is(err, ErrLocksmithNotFound) {
			return "", err
		}
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
