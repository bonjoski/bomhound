package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}

	if cfg.Version != "1" {
		t.Errorf("expected Version '1', got %q", cfg.Version)
	}

	if cfg.Cache.TTLDays != 30 {
		t.Errorf("expected Cache.TTLDays 30, got %d", cfg.Cache.TTLDays)
	}

	if cfg.Cache.Dir == "" {
		t.Error("expected non-empty Cache.Dir")
	}

	if cfg.Compliance.MinCoveragePercent != 0.0 {
		t.Errorf("expected Compliance.MinCoveragePercent 0.0, got %f", cfg.Compliance.MinCoveragePercent)
	}

	if cfg.Compliance.FailOnMissing {
		t.Error("expected Compliance.FailOnMissing to be false")
	}

	if cfg.Exclude.PURLs == nil || cfg.Exclude.Names == nil || cfg.VanityURLs == nil {
		t.Error("expected non-nil slices and maps in DefaultConfig")
	}
}

func TestLoadConfig_ExplicitPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "custom-config.yaml")

	yamlContent := `
version: "2"
exclude:
  purls:
    - "pkg:golang/github.com/excluded/*"
    - "pkg:npm/@types/*"
  names:
    - "internal-*"
    - "secret-pkg"
vanity_urls:
  software.sslmate.com/src/go-pkcs12: github.com/sslmate/go-pkcs12
cache:
  dir: /custom/cache
  ttl_days: 14
compliance:
  min_coverage_percent: 85.5
  fail_on_missing: true
`
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.Version != "2" {
		t.Errorf("expected Version '2', got %q", cfg.Version)
	}
	if len(cfg.Exclude.PURLs) != 2 || cfg.Exclude.PURLs[0] != "pkg:golang/github.com/excluded/*" {
		t.Errorf("unexpected Exclude.PURLs: %v", cfg.Exclude.PURLs)
	}
	if len(cfg.Exclude.Names) != 2 || cfg.Exclude.Names[0] != "internal-*" {
		t.Errorf("unexpected Exclude.Names: %v", cfg.Exclude.Names)
	}
	if cfg.VanityURLs["software.sslmate.com/src/go-pkcs12"] != "github.com/sslmate/go-pkcs12" {
		t.Errorf("unexpected VanityURLs: %v", cfg.VanityURLs)
	}
	if cfg.Cache.Dir != "/custom/cache" {
		t.Errorf("expected Cache.Dir '/custom/cache', got %q", cfg.Cache.Dir)
	}
	if cfg.Cache.TTLDays != 14 {
		t.Errorf("expected Cache.TTLDays 14, got %d", cfg.Cache.TTLDays)
	}
	if cfg.Compliance.MinCoveragePercent != 85.5 {
		t.Errorf("expected Compliance.MinCoveragePercent 85.5, got %f", cfg.Compliance.MinCoveragePercent)
	}
	if !cfg.Compliance.FailOnMissing {
		t.Error("expected Compliance.FailOnMissing to be true")
	}
}

func TestLoadConfig_NonExistentAndInvalid(t *testing.T) {
	// Non-existent path
	_, err := LoadConfig("/non/existent/path/bomhound.yaml")
	if err == nil {
		t.Error("expected error for non-existent config path, got nil")
	}

	// Invalid YAML syntax
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte("invalid: [yaml: broken"), 0644); err != nil {
		t.Fatalf("failed to write invalid file: %v", err)
	}

	_, err = LoadConfig(invalidFile)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoadConfig_EmptyPathDefaults(t *testing.T) {
	// Move to a clean temp directory with no config files
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	defer os.Chdir(origWd)

	tmpDir := t.TempDir()
	// Create a nested subdir to ensure no config files exist upwards up to 3 levels
	deepDir := filepath.Join(tmpDir, "a", "b", "c", "d")
	if err := os.MkdirAll(deepDir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	if err := os.Chdir(deepDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	// Ensure HOME doesn't point to an existing ~/.config/bomhound/config.yaml for this test
	t.Setenv("HOME", filepath.Join(tmpDir, "fakehome"))

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("expected nil error when no config file found, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if cfg.Version != "1" {
		t.Errorf("expected Version '1', got %q", cfg.Version)
	}
}

func TestLoadConfig_SearchHierarchy(t *testing.T) {
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	defer os.Chdir(origWd)

	// Test 1: Found in current directory as .bomhound.yaml
	{
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, ".bomhound.yaml")
		_ = os.WriteFile(cfgFile, []byte("version: \"current-yaml\"\n"), 0644)
		_ = os.Chdir(tmpDir)

		cfg, err := LoadConfig("")
		if err != nil || cfg.Version != "current-yaml" {
			t.Errorf("failed to load .bomhound.yaml in current dir: err=%v, version=%s", err, cfg.Version)
		}
	}

	// Test 2: Found in current directory as .bomhound.yml
	{
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, ".bomhound.yml")
		_ = os.WriteFile(cfgFile, []byte("version: \"current-yml\"\n"), 0644)
		_ = os.Chdir(tmpDir)

		cfg, err := LoadConfig("")
		if err != nil || cfg.Version != "current-yml" {
			t.Errorf("failed to load .bomhound.yml in current dir: err=%v, version=%s", err, cfg.Version)
		}
	}

	// Test 3: Found 3 levels up
	{
		tmpDir := t.TempDir()
		// Structure: tmpDir/.bomhound.yaml
		// Sub: tmpDir/l1/l2/l3
		l3Dir := filepath.Join(tmpDir, "l1", "l2", "l3")
		_ = os.MkdirAll(l3Dir, 0755)
		_ = os.WriteFile(filepath.Join(tmpDir, ".bomhound.yaml"), []byte("version: \"level-3-up\"\n"), 0644)
		_ = os.Chdir(l3Dir)

		cfg, err := LoadConfig("")
		if err != nil || cfg.Version != "level-3-up" {
			t.Errorf("failed to load config 3 levels up: err=%v, version=%v", err, cfg)
		}
	}

	// Test 4: NOT found 4 levels up (only checks up to 3 levels)
	{
		tmpDir := t.TempDir()
		l4Dir := filepath.Join(tmpDir, "l1", "l2", "l3", "l4")
		_ = os.MkdirAll(l4Dir, 0755)
		_ = os.WriteFile(filepath.Join(tmpDir, ".bomhound.yaml"), []byte("version: \"level-4-up\"\n"), 0644)
		_ = os.Chdir(l4Dir)
		t.Setenv("HOME", filepath.Join(tmpDir, "fakehome"))

		cfg, err := LoadConfig("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should fall back to default ("1") since 4 levels up is beyond 3
		if cfg.Version == "level-4-up" {
			t.Errorf("should not have loaded config 4 levels up")
		}
	}

	// Test 5: Found in ~/.config/bomhound/config.yaml
	{
		tmpDir := t.TempDir()
		workDir := filepath.Join(tmpDir, "work")
		fakeHome := filepath.Join(tmpDir, "home")
		configDir := filepath.Join(fakeHome, ".config", "bomhound")
		_ = os.MkdirAll(workDir, 0755)
		_ = os.MkdirAll(configDir, 0755)
		_ = os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("version: \"xdg-home-cfg\"\n"), 0644)

		_ = os.Chdir(workDir)
		t.Setenv("HOME", fakeHome)

		cfg, err := LoadConfig("")
		if err != nil || cfg.Version != "xdg-home-cfg" {
			t.Errorf("failed to load ~/.config/bomhound/config.yaml: err=%v, version=%v", err, cfg)
		}
	}
}

func TestConfig_IsExcluded(t *testing.T) {
	cfg := &Config{
		Exclude: ExcludeConfig{
			PURLs: []string{
				"pkg:golang/*",
				"pkg:npm/@types/*",
				"pkg:pypi/test-pkg@1.0.0",
				"pkg:maven/com.internal.*",
				"pkg:cargo/v[0-9]*",
				"pkg:nuget/app-?",
			},
			Names: []string{
				"internal-*",
				"*test*",
				"lodash",
			},
		},
	}

	tests := []struct {
		name         string
		purl         string
		compName     string
		wantExcluded bool
		wantPattern  string
	}{
		{
			name:         "purl prefix match with wildcard",
			purl:         "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			compName:     "gin",
			wantExcluded: true,
			wantPattern:  "pkg:golang/*",
		},
		{
			name:         "purl scoped npm wildcard",
			purl:         "pkg:npm/@types/node@18.0.0",
			compName:     "@types/node",
			wantExcluded: true,
			wantPattern:  "pkg:npm/@types/*",
		},
		{
			name:         "purl exact match",
			purl:         "pkg:pypi/test-pkg@1.0.0",
			compName:     "other",
			wantExcluded: true,
			wantPattern:  "pkg:pypi/test-pkg@1.0.0",
		},
		{
			name:         "purl maven wildcard",
			purl:         "pkg:maven/com.internal.service/auth@1.0",
			compName:     "auth",
			wantExcluded: true,
			wantPattern:  "pkg:maven/com.internal.*",
		},
		{
			name:         "name glob prefix match",
			purl:         "pkg:npm/internal-tools@1.0.0",
			compName:     "internal-tools",
			wantExcluded: true,
			wantPattern:  "internal-*",
		},
		{
			name:         "name contains wildcard match",
			purl:         "pkg:npm/my-test-package@1.0.0",
			compName:     "my-test-package",
			wantExcluded: true,
			wantPattern:  "*test*",
		},
		{
			name:         "name exact match",
			purl:         "pkg:npm/lodash@4.17.21",
			compName:     "lodash",
			wantExcluded: true,
			wantPattern:  "lodash",
		},
		{
			name:         "name case-insensitive match",
			purl:         "pkg:npm/Lodash@4.17.21",
			compName:     "Lodash",
			wantExcluded: true,
			wantPattern:  "lodash",
		},
		{
			name:         "purl character class range match",
			purl:         "pkg:cargo/v1-alpha",
			compName:     "v1-alpha",
			wantExcluded: true,
			wantPattern:  "pkg:cargo/v[0-9]*",
		},
		{
			name:         "purl question mark match",
			purl:         "pkg:nuget/app-1",
			compName:     "app-1",
			wantExcluded: true,
			wantPattern:  "pkg:nuget/app-?",
		},
		{
			name:         "no match",
			purl:         "pkg:npm/express@4.18.2",
			compName:     "express",
			wantExcluded: false,
			wantPattern:  "",
		},
		{
			name:         "empty purl but matching name",
			purl:         "",
			compName:     "internal-auth",
			wantExcluded: true,
			wantPattern:  "internal-*",
		},
		{
			name:         "matching purl with empty name",
			purl:         "pkg:golang/x/crypto",
			compName:     "",
			wantExcluded: true,
			wantPattern:  "pkg:golang/*",
		},
		{
			name:         "both empty",
			purl:         "",
			compName:     "",
			wantExcluded: false,
			wantPattern:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			excluded, pattern := cfg.IsExcluded(tc.purl, tc.compName)
			if excluded != tc.wantExcluded {
				t.Errorf("IsExcluded(%q, %q) got excluded=%v, want %v", tc.purl, tc.compName, excluded, tc.wantExcluded)
			}
			if pattern != tc.wantPattern {
				t.Errorf("IsExcluded(%q, %q) got pattern=%q, want %q", tc.purl, tc.compName, pattern, tc.wantPattern)
			}
		})
	}
}

func TestLoadConfig_TildePath(t *testing.T) {
	tmpDir := t.TempDir()
	fakeHome := filepath.Join(tmpDir, "home")
	_ = os.MkdirAll(fakeHome, 0755)
	cfgFile := filepath.Join(fakeHome, "test-tilde-config.yaml")
	_ = os.WriteFile(cfgFile, []byte("version: \"tilde-path\"\n"), 0644)

	t.Setenv("HOME", fakeHome)

	cfg, err := LoadConfig("~/test-tilde-config.yaml")
	if err != nil {
		t.Fatalf("unexpected error loading config with tilde: %v", err)
	}
	if cfg.Version != "tilde-path" {
		t.Errorf("expected Version 'tilde-path', got %q", cfg.Version)
	}
}

func TestLoadConfig_EmptyYamlSections(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "empty.yaml")
	_ = os.WriteFile(cfgFile, []byte("version: \"empty-test\"\n"), 0644)

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Exclude.PURLs == nil || cfg.Exclude.Names == nil || cfg.VanityURLs == nil {
		t.Errorf("expected initialized non-nil slices and maps")
	}
}

func TestConfig_IsExcluded_WildcardsAndEdgeCases(t *testing.T) {
	cfg := &Config{
		Exclude: ExcludeConfig{
			Names: []string{"*", "[unclosed"},
		},
	}
	excluded, pattern := cfg.IsExcluded("", "any-name")
	if !excluded || pattern != "*" {
		t.Errorf("expected wildcard match on '*', got %v, %q", excluded, pattern)
	}

	cfg2 := &Config{
		Exclude: ExcludeConfig{
			Names: []string{"[unclosed"},
		},
	}
	excluded, pattern = cfg2.IsExcluded("", "[unclosed")
	if !excluded || pattern != "[unclosed" {
		t.Errorf("expected match on '[unclosed', got %v, %q", excluded, pattern)
	}
}

func TestConfig_IsExcluded_NilReceiver(t *testing.T) {
	var cfg *Config
	excluded, pattern := cfg.IsExcluded("pkg:golang/test", "test")
	if excluded || pattern != "" {
		t.Errorf("expected false, \"\" for nil config, got %v, %q", excluded, pattern)
	}
}
