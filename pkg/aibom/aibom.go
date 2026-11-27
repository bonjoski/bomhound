package aibom

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"gopkg.in/yaml.v3"
)

const (
	// MaxAIBOMConfigBytes caps .ai-bom.yaml size to 4 MiB to prevent memory exhaustion.
	MaxAIBOMConfigBytes = 4 << 20

	// Supported AI component types for .ai-bom.yaml.
	TypeMLModel      = "machine-learning-model"
	TypeMCPServer    = "mcp-server"
	TypeAgentRuntime = "agent-runtime"
)

var (
	// ErrPathTraversal indicates a rejected path traversal or absolute path attempt.
	ErrPathTraversal = errors.New("ai-bom path traversal rejected")

	// ErrSymlinkRejected indicates a symlink was encountered inside the confined root.
	ErrSymlinkRejected = errors.New("refusing to read symlinked ai-bom file")
)

// AIBOMConfig models the repository-local .ai-bom.yaml schema.
type AIBOMConfig struct {
	Version    string                  `yaml:"version,omitempty" json:"version,omitempty"`
	Components []AIComponentDescriptor `yaml:"components" json:"components"`
}

// AIComponentDescriptor describes a local AI model, MCP server, or agent runtime
// to be emitted as a CycloneDX 1.6 component.
type AIComponentDescriptor struct {
	Name          string            `yaml:"name" json:"name"`
	Type          string            `yaml:"type" json:"type"` // "machine-learning-model" | "mcp-server" | "agent-runtime"
	Version       string            `yaml:"version" json:"version"`
	Provider      string            `yaml:"provider,omitempty" json:"provider,omitempty"`
	ModelDigest   string            `yaml:"sha256,omitempty" json:"sha256,omitempty"`
	AirGapCapable bool              `yaml:"airgap_capable" json:"airgap_capable"`
	License       string            `yaml:"license,omitempty" json:"license,omitempty"`
	URL           string            `yaml:"url,omitempty" json:"url,omitempty"`
	Description   string            `yaml:"description,omitempty" json:"description,omitempty"`
	Properties    map[string]string `yaml:"properties,omitempty" json:"properties,omitempty"`
}

// LoadAIBOMConfig loads and validates a .ai-bom.yaml file strictly confined within rootDir
// using os.OpenRoot, refusing symlinks and path traversal escapes.
func LoadAIBOMConfig(rootDir, relPath string) (*AIBOMConfig, error) {
	if strings.TrimSpace(rootDir) == "" {
		return nil, errors.New("rootDir cannot be empty")
	}
	if strings.TrimSpace(relPath) == "" {
		return nil, errors.New("relPath cannot be empty")
	}
	if strings.ContainsRune(relPath, '\x00') {
		return nil, fmt.Errorf("%w: null byte in path", ErrPathTraversal)
	}
	if filepath.IsAbs(relPath) || strings.HasPrefix(relPath, "/") || strings.HasPrefix(relPath, "\\") {
		return nil, fmt.Errorf("%w: absolute path %q not permitted", ErrPathTraversal, relPath)
	}

	// Reject any raw '..' segment before cleaning.
	normalizedSlashes := strings.ReplaceAll(relPath, "\\", "/")
	for _, seg := range strings.Split(normalizedSlashes, "/") {
		if seg == ".." {
			return nil, fmt.Errorf("%w: parent traversal in %q", ErrPathTraversal, relPath)
		}
	}

	cleaned := filepath.Clean(relPath)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || filepath.IsAbs(cleaned) {
		return nil, fmt.Errorf("%w: invalid relative path %q", ErrPathTraversal, relPath)
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, fmt.Errorf("open confined root %q: %w", rootDir, err)
	}
	defer root.Close()

	// Verify every path segment inside rootDir is not a symlink using root.Lstat.
	parts := strings.Split(filepath.ToSlash(cleaned), "/")
	cur := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if cur == "" {
			cur = part
		} else {
			cur = cur + "/" + part
		}
		fi, err := root.Lstat(cur)
		if err != nil {
			return nil, fmt.Errorf("lstat %q inside root: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s", ErrSymlinkRejected, cur)
		}
	}

	fi, err := root.Lstat(cleaned)
	if err != nil {
		return nil, fmt.Errorf("lstat %q: %w", cleaned, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlinkRejected, cleaned)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("ai-bom target %q is not a regular file", cleaned)
	}
	if fi.Size() > MaxAIBOMConfigBytes {
		return nil, fmt.Errorf("ai-bom config exceeds maximum allowed size (%d bytes)", MaxAIBOMConfigBytes)
	}

	f, err := root.Open(cleaned)
	if err != nil {
		return nil, fmt.Errorf("open %q inside confined root: %w", cleaned, err)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, MaxAIBOMConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", cleaned, err)
	}
	if len(raw) > MaxAIBOMConfigBytes {
		return nil, fmt.Errorf("ai-bom config exceeds maximum allowed size (%d bytes)", MaxAIBOMConfigBytes)
	}

	return ParseAIBOMConfig(raw)
}

// ParseAIBOMConfig decodes and validates YAML bytes representing a .ai-bom.yaml file.
func ParseAIBOMConfig(data []byte) (*AIBOMConfig, error) {
	if len(data) > MaxAIBOMConfigBytes {
		return nil, fmt.Errorf("ai-bom config exceeds maximum allowed size (%d bytes)", MaxAIBOMConfigBytes)
	}
	var cfg AIBOMConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse ai-bom yaml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks schema invariants on all declared AI components.
func (c *AIBOMConfig) Validate() error {
	if c == nil {
		return errors.New("ai-bom config is nil")
	}
	for i, comp := range c.Components {
		if strings.TrimSpace(comp.Name) == "" {
			return fmt.Errorf("components[%d]: name is required", i)
		}
		if strings.TrimSpace(comp.Version) == "" {
			return fmt.Errorf("components[%d] (%s): version is required", i, comp.Name)
		}
		switch comp.Type {
		case TypeMLModel, TypeMCPServer, TypeAgentRuntime:
		default:
			return fmt.Errorf("components[%d] (%s): unsupported type %q (expected %q, %q, or %q)",
				i, comp.Name, comp.Type, TypeMLModel, TypeMCPServer, TypeAgentRuntime)
		}
		if comp.ModelDigest != "" && !isValidSHA256Hex(strings.ToLower(strings.TrimSpace(comp.ModelDigest))) {
			return fmt.Errorf("components[%d] (%s): sha256 must be a valid 64-character hex digest", i, comp.Name)
		}
		if comp.URL != "" && !strings.HasPrefix(comp.URL, "https://") && !strings.HasPrefix(comp.URL, "http://") {
			return fmt.Errorf("components[%d] (%s): url must use https:// or http:// scheme", i, comp.Name)
		}
	}
	return nil
}

// InjectAIBOM appends CycloneDX 1.6 AI-BOM components into bom without mutating
// any existing components' hashes, copyrights, or metadata.
func InjectAIBOM(bom *cdx.BOM, cfg *AIBOMConfig) error {
	if bom == nil {
		return errors.New("cannot inject AI-BOM into nil BOM")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if len(cfg.Components) == 0 {
		return nil
	}

	// Upgrade specVersion to CycloneDX 1.6 if older so machine-learning-model & modelCard are valid.
	if bom.SpecVersion < cdx.SpecVersion1_6 {
		bom.SpecVersion = cdx.SpecVersion1_6
	}

	existing := make(map[string]struct{})
	var comps []cdx.Component
	if bom.Components != nil {
		comps = make([]cdx.Component, len(*bom.Components), len(*bom.Components)+len(cfg.Components))
		copy(comps, *bom.Components)
		for _, c := range comps {
			if c.BOMRef != "" {
				existing[c.BOMRef] = struct{}{}
			}
		}
	} else {
		comps = make([]cdx.Component, 0, len(cfg.Components))
	}

	for _, desc := range cfg.Components {
		comp := buildCDXComponent(desc)
		if _, dup := existing[comp.BOMRef]; dup {
			continue
		}
		existing[comp.BOMRef] = struct{}{}
		comps = append(comps, comp)
	}

	bom.Components = &comps
	return nil
}

// InjectAIBOMJSON parses CycloneDX JSON bytes, injects AI-BOM components without mutating
// existing components' hashes or copyrights, and returns pretty-printed CycloneDX 1.6 JSON.
func InjectAIBOMJSON(sbomJSON []byte, cfg *AIBOMConfig) ([]byte, error) {
	bom := cdx.NewBOM()
	decoder := cdx.NewBOMDecoder(bytes.NewReader(sbomJSON), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("decode CycloneDX SBOM JSON: %w", err)
	}
	if err := InjectAIBOM(bom, cfg); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	encoder := cdx.NewBOMEncoder(&out, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		return nil, fmt.Errorf("encode CycloneDX 1.6 SBOM JSON: %w", err)
	}
	return out.Bytes(), nil
}

func buildCDXComponent(desc AIComponentDescriptor) cdx.Component {
	cdxType := cdx.ComponentTypeApplication
	if desc.Type == TypeMLModel {
		cdxType = cdx.ComponentTypeMachineLearningModel
	}

	bomRef := fmt.Sprintf("ai-bom:%s:%s@%s", desc.Type, desc.Name, desc.Version)
	comp := cdx.Component{
		BOMRef:      bomRef,
		Type:        cdxType,
		Name:        desc.Name,
		Version:     desc.Version,
		Description: desc.Description,
	}

	if desc.Provider != "" {
		comp.Supplier = &cdx.OrganizationalEntity{
			Name: desc.Provider,
		}
	}

	if desc.ModelDigest != "" {
		hashes := []cdx.Hash{
			{
				Algorithm: cdx.HashAlgoSHA256,
				Value:     strings.ToLower(strings.TrimSpace(desc.ModelDigest)),
			},
		}
		comp.Hashes = &hashes
	}

	if desc.License != "" {
		licenses := cdx.Licenses{
			{
				License: &cdx.License{
					ID: desc.License,
				},
			},
		}
		comp.Licenses = &licenses
	}

	if desc.URL != "" {
		refs := []cdx.ExternalReference{
			{
				Type: cdx.ERTypeWebsite,
				URL:  desc.URL,
			},
		}
		comp.ExternalReferences = &refs
	}

	props := []cdx.Property{
		{Name: "bonjoski:aibom:airgap_capable", Value: strconv.FormatBool(desc.AirGapCapable)},
		{Name: "bonjoski:aibom:category", Value: desc.Type},
	}
	if desc.Provider != "" {
		props = append(props, cdx.Property{Name: "bonjoski:aibom:provider", Value: desc.Provider})
	}
	if len(desc.Properties) > 0 {
		keys := make([]string, 0, len(desc.Properties))
		for k := range desc.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			name := k
			if !strings.HasPrefix(name, "bonjoski:aibom:") {
				name = "bonjoski:aibom:" + name
			}
			props = append(props, cdx.Property{Name: name, Value: desc.Properties[k]})
		}
	}
	comp.Properties = &props

	if desc.Type == TypeMLModel {
		comp.ModelCard = &cdx.MLModelCard{
			BOMRef: bomRef + ":card",
		}
	}

	return comp
}

func isValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
