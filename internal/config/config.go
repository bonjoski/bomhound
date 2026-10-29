package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the configuration for bomhound.
type Config struct {
	Version    string            `yaml:"version"`
	Auth       AuthConfig        `yaml:"auth"`
	Exclude    ExcludeConfig     `yaml:"exclude"`
	VanityURLs map[string]string `yaml:"vanity_urls"`
	Cache      CacheConfig       `yaml:"cache"`
	Compliance ComplianceConfig  `yaml:"compliance"`
}

// AuthConfig specifies authentication and credential provider settings.
type AuthConfig struct {
	LocksmithKey string `yaml:"locksmith_key"`
}

// ExcludeConfig specifies patterns for excluding components from enrichment.
type ExcludeConfig struct {
	PURLs []string `yaml:"purls"`
	Names []string `yaml:"names"`
}

// CacheConfig specifies local cache settings.
type CacheConfig struct {
	Dir     string `yaml:"dir"`
	TTLDays int    `yaml:"ttl_days"`
}

// ComplianceConfig specifies compliance thresholds.
type ComplianceConfig struct {
	MinCoveragePercent float64 `yaml:"min_coverage_percent"`
	FailOnMissing      bool    `yaml:"fail_on_missing"`
}

// DefaultConfig returns a Config instance with sensible defaults.
func DefaultConfig() *Config {
	home, err := os.UserHomeDir()
	cacheDir := ".cache/bomhound"
	if err == nil && home != "" {
		cacheDir = filepath.Join(home, ".cache", "bomhound")
	}

	return &Config{
		Version: "1",
		Exclude: ExcludeConfig{
			PURLs: []string{},
			Names: []string{},
		},
		VanityURLs: make(map[string]string),
		Cache: CacheConfig{
			Dir:     cacheDir,
			TTLDays: 30,
		},
		Compliance: ComplianceConfig{
			MinCoveragePercent: 0.0,
			FailOnMissing:      false,
		},
	}
}

// LoadConfig loads the configuration from path or default locations.
// If path is empty, it searches for .bomhound.yaml, .bomhound.yml in the current directory,
// upwards up to 3 levels, or ~/.config/bomhound/config.yaml.
// If no configuration file is found, DefaultConfig() is returned without error.
func LoadConfig(pathStr string) (*Config, error) {
	var configPath string

	if pathStr != "" {
		configPath = pathStr
		if strings.HasPrefix(configPath, "~/") {
			home, err := os.UserHomeDir()
			if err == nil && home != "" {
				configPath = filepath.Join(home, configPath[2:])
			}
		}
	} else {
		configPath = findConfigFile()
		if configPath == "" {
			return DefaultConfig(), nil
		}
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", configPath, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", configPath, err)
	}

	// Ensure non-nil slices and maps
	if cfg.VanityURLs == nil {
		cfg.VanityURLs = make(map[string]string)
	}
	if cfg.Exclude.PURLs == nil {
		cfg.Exclude.PURLs = []string{}
	}
	if cfg.Exclude.Names == nil {
		cfg.Exclude.Names = []string{}
	}

	return cfg, nil
}

// findConfigFile searches for .bomhound.yaml / .bomhound.yml in current dir,
// upwards up to 3 levels, or ~/.config/bomhound/config.yaml.
func findConfigFile() string {
	currDir, err := os.Getwd()
	if err == nil {
		dir := currDir
		for level := 0; level <= 3; level++ {
			for _, filename := range []string{".bomhound.yaml", ".bomhound.yml"} {
				candidate := filepath.Join(dir, filename)
				if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
					return candidate
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		for _, filename := range []string{"config.yaml", "config.yml"} {
			candidate := filepath.Join(home, ".config", "bomhound", filename)
			if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
				return candidate
			}
		}
	}

	return ""
}

// IsExcluded checks if a component is excluded based on its PURL or name.
// It checks prefix and glob matches against Exclude.PURLs and Exclude.Names.
// If excluded, it returns true and the matching pattern. Otherwise, it returns false, "".
func (c *Config) IsExcluded(purl, name string) (bool, string) {
	if c == nil {
		return false, ""
	}

	purl = strings.TrimSpace(purl)
	name = strings.TrimSpace(name)

	if purl != "" {
		for _, pattern := range c.Exclude.PURLs {
			if matchPattern(purl, strings.TrimSpace(pattern)) {
				return true, pattern
			}
		}
	}

	if name != "" {
		for _, pattern := range c.Exclude.Names {
			if matchPattern(name, strings.TrimSpace(pattern)) {
				return true, pattern
			}
		}
	}

	return false, ""
}

func matchPattern(target, pattern string) bool {
	if pattern == "" || target == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if target == pattern || strings.EqualFold(target, pattern) {
		return true
	}
	if strings.HasPrefix(target, pattern) || strings.HasPrefix(strings.ToLower(target), strings.ToLower(pattern)) {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(target, prefix) || strings.HasPrefix(strings.ToLower(target), strings.ToLower(prefix)) {
			return true
		}
	}
	if matched, _ := path.Match(pattern, target); matched {
		return true
	}
	if matched, _ := filepath.Match(pattern, target); matched {
		return true
	}
	if re, err := globToRegexp(pattern); err == nil {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

func globToRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			// Collapse redundant consecutive asterisks to prevent exponential NFA states
			for i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
			}
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '.', '+', '(', ')', '^', '$', '|', '{', '}':
			b.WriteString("\\")
			b.WriteByte(c)
		case '\\':
			if i+1 < len(pattern) {
				i++
				b.WriteString("\\")
				b.WriteByte(pattern[i])
			} else {
				b.WriteString("\\\\")
			}
		case '[':
			j := i + 1
			if j < len(pattern) && pattern[j] == ']' {
				j++
			}
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				b.WriteString(pattern[i : j+1])
				i = j
			} else {
				b.WriteString("\\[")
			}
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
