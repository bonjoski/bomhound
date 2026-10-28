package auth

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

func resetHooks() {
	isTerminal = func(fd int) bool { return false }
	readPassword = func(fd int) ([]byte, error) { return nil, errors.New("not implemented") }
	keyringGet = keyring.Get
	keyringSet = keyring.Set
	keyringDelete = keyring.Delete
}

func TestGetGitHubToken_GitHubTokenEnv(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "ghp_from_github_token")
	t.Setenv("GH_TOKEN", "")

	token, err := GetGitHubToken()
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

	token, err := GetGitHubToken()
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

	token, err := GetGitHubToken()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "ghp_primary" {
		t.Fatalf("expected ghp_primary, got: %s", token)
	}
}

func TestGetGitHubToken_NonTerminalCI(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	isTerminal = func(fd int) bool {
		return false
	}

	token, err := GetGitHubToken()
	if err == nil {
		t.Fatalf("expected error in non-terminal CI environment, got token: %q", token)
	}
	if !errors.Is(err, ErrTokenNotFoundInCI) {
		t.Fatalf("expected ErrTokenNotFoundInCI, got: %v", err)
	}
}

func TestGetGitHubToken_TerminalFoundInKeyring(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	isTerminal = func(fd int) bool {
		return true
	}
	keyringGet = func(service, user string) (string, error) {
		if service == serviceName && user == userName {
			return "ghp_saved_in_keyring", nil
		}
		return "", keyring.ErrNotFound
	}

	token, err := GetGitHubToken()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "ghp_saved_in_keyring" {
		t.Fatalf("expected ghp_saved_in_keyring, got: %s", token)
	}
}

func TestGetGitHubToken_TerminalPromptAndSave(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	isTerminal = func(fd int) bool {
		return true
	}
	keyringGet = func(service, user string) (string, error) {
		return "", keyring.ErrNotFound
	}

	var savedService, savedUser, savedToken string
	keyringSet = func(service, user, password string) error {
		savedService = service
		savedUser = user
		savedToken = password
		return nil
	}
	readPassword = func(fd int) ([]byte, error) {
		return []byte("  ghp_prompted_secret  \n"), nil
	}

	token, err := GetGitHubToken()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if token != "ghp_prompted_secret" {
		t.Fatalf("expected trimmed ghp_prompted_secret, got: %s", token)
	}
	if savedService != serviceName || savedUser != userName || savedToken != "ghp_prompted_secret" {
		t.Fatalf("keyringSet called with unexpected values: service=%s user=%s token=%s", savedService, savedUser, savedToken)
	}
}

func TestGetGitHubToken_TerminalPromptEmptyToken(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	isTerminal = func(fd int) bool {
		return true
	}
	keyringGet = func(service, user string) (string, error) {
		return "", keyring.ErrNotFound
	}
	readPassword = func(fd int) ([]byte, error) {
		return []byte("   "), nil
	}

	_, err := GetGitHubToken()
	if !errors.Is(err, ErrEmptyToken) {
		t.Fatalf("expected ErrEmptyToken, got: %v", err)
	}
}

func TestGetGitHubToken_TerminalReadPasswordError(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	isTerminal = func(fd int) bool {
		return true
	}
	keyringGet = func(service, user string) (string, error) {
		return "", keyring.ErrNotFound
	}
	readPassword = func(fd int) ([]byte, error) {
		return nil, errors.New("read error")
	}

	_, err := GetGitHubToken()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetGitHubToken_TerminalKeyringSetError(t *testing.T) {
	defer resetHooks()

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	isTerminal = func(fd int) bool {
		return true
	}
	keyringGet = func(service, user string) (string, error) {
		return "", keyring.ErrNotFound
	}
	readPassword = func(fd int) ([]byte, error) {
		return []byte("ghp_valid_token"), nil
	}
	keyringSet = func(service, user, password string) error {
		return errors.New("keyring storage failed")
	}

	_, err := GetGitHubToken()
	if err == nil {
		t.Fatal("expected error when saving to keyring, got nil")
	}
}

func TestClearToken(t *testing.T) {
	defer resetHooks()

	var deletedService, deletedUser string
	keyringDelete = func(service, user string) error {
		deletedService = service
		deletedUser = user
		return nil
	}

	err := ClearToken()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if deletedService != serviceName || deletedUser != userName {
		t.Fatalf("keyringDelete called with unexpected args: %s, %s", deletedService, deletedUser)
	}
}
