package cra

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// ErrSecretDetected is returned fail-closed when credential patterns or high-entropy secrets
// are detected inside any CRA bundle input artifact.
var ErrSecretDetected = errors.New("secret or credential token detected in CRA bundle artifact")

type secretRule struct {
	name string
	re   *regexp.Regexp
}

var secretPatternRules = []secretRule{
	{name: "aws-access-key-id", re: regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`)},
	{name: "github-token", re: regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`)},
	{name: "github-fine-grained-pat", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{name: "anthropic-api-key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9\-_]{16,}\b`)},
	{name: "openai-api-key", re: regexp.MustCompile(`\bsk-(?:proj|live|test)-[A-Za-z0-9\-_]{16,}\b`)},
	{name: "stripe-secret-key", re: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`)},
	{name: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{16,}\b`)},
	{name: "gcp-api-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{name: "private-key-pem", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
	{name: "bearer-credential", re: regexp.MustCompile(`(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*`)},
}

// secretAssignmentRe catches key=value / key: value lines assigning high-entropy tokens to sensitive keys.
var secretAssignmentRe = regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|secret[_-]?key|password|passwd|credential)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{20,})["']?`)

// ScanForSecrets inspects artifact content for known credential prefixes, PEM private keys,
// and high-entropy secret assignments. Never echoes the secret value in returned errors.
func ScanForSecrets(artifactName string, content []byte) error {
	if len(content) == 0 {
		return nil
	}
	text := string(content)

	for _, rule := range secretPatternRules {
		if rule.re.MatchString(text) {
			return fmt.Errorf("%w: matched rule %q in %s", ErrSecretDetected, rule.name, artifactName)
		}
	}

	matches := secretAssignmentRe.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		candidate := m[1]
		if isLikelySafeDigestOrPlaceholder(candidate) {
			continue
		}
		if shannonEntropy(candidate) >= 3.8 {
			return fmt.Errorf("%w: high-entropy credential assignment in %s", ErrSecretDetected, artifactName)
		}
	}

	return nil
}

func isLikelySafeDigestOrPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "example") || strings.Contains(lower, "placeholder") || strings.Contains(lower, "changeme") || strings.Contains(lower, "redacted") {
		return true
	}
	// Pure lowercase hex of standard digest lengths (SHA-256 = 64, SHA-512 = 128) is typically a hash, not an API key.
	if len(s) == 64 || len(s) == 128 {
		allHex := true
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
