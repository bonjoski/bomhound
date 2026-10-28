package auth

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const (
	serviceName = "bomhound"
	userName    = "github-token"
)

var (
	// ErrTokenNotFoundInCI is returned when no token env var is set in a non-terminal (CI/headless) environment.
	ErrTokenNotFoundInCI = errors.New("GitHub token not found: please set GITHUB_TOKEN or GH_TOKEN environment variable in CI/headless environments")
	// ErrEmptyToken is returned when an entered token is blank.
	ErrEmptyToken = errors.New("token cannot be empty")
)

// Internal hooks for testing
var (
	isTerminal    = term.IsTerminal
	readPassword  = term.ReadPassword
	keyringGet    = keyring.Get
	keyringSet    = keyring.Set
	keyringDelete = keyring.Delete
)

// GetGitHubToken retrieves the GitHub token from environment variables, keyring, or interactive prompt.
func GetGitHubToken() (string, error) {
	// a) Check GITHUB_TOKEN or GH_TOKEN env vars
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
		return token, nil
	}
	if token := strings.TrimSpace(os.Getenv("GH_TOKEN")); token != "" {
		return token, nil
	}

	// b) Check if stdin is a terminal
	stdinFd := int(os.Stdin.Fd())
	if !isTerminal(stdinFd) {
		// d) Non-terminal / CI headless environment
		return "", ErrTokenNotFoundInCI
	}

	// c) Terminal: check keyring
	token, err := keyringGet(serviceName, userName)
	if err == nil && strings.TrimSpace(token) != "" {
		return strings.TrimSpace(token), nil
	}

	// Not in keyring, prompt interactively
	fmt.Print("GitHub Token not found in keyring.\n")
	fmt.Print("Please enter your GitHub Token (input will be hidden): ")

	byteToken, err := readPassword(stdinFd)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println() // Print a newline after input

	token = strings.TrimSpace(string(byteToken))
	if token == "" {
		return "", ErrEmptyToken
	}

	// Save to keyring
	err = keyringSet(serviceName, userName, token)
	if err != nil {
		return "", fmt.Errorf("failed to save token to keyring: %w", err)
	}

	fmt.Println("Token saved to keyring.")
	return token, nil
}

// ClearToken removes the token from the keyring (useful for testing or resetting).
func ClearToken() error {
	return keyringDelete(serviceName, userName)
}
