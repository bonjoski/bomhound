package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// DetectFormat sniffs the first non-whitespace bytes to determine JSON or XML format.
func DetectFormat(r io.Reader) (cdx.BOMFileFormat, io.Reader, error) {
	br := bufio.NewReader(r)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return cdx.BOMFileFormatJSON, br, fmt.Errorf("reading stream to detect format: %w", err)
		}
		// Skip whitespace
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		if err := br.UnreadByte(); err != nil {
			return cdx.BOMFileFormatJSON, br, fmt.Errorf("unreading byte: %w", err)
		}
		if b == '<' {
			return cdx.BOMFileFormatXML, br, nil
		}
		return cdx.BOMFileFormatJSON, br, nil
	}
}

// ParseSBOM parses a CycloneDX SBOM from a file path while preserving its native schema and format.
func ParseSBOM(filePath string) (*cdx.BOM, cdx.BOMFileFormat, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, cdx.BOMFileFormatJSON, fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer file.Close()

	format, reader, err := DetectFormat(file)
	if err != nil {
		return nil, cdx.BOMFileFormatJSON, fmt.Errorf("detecting SBOM format: %w", err)
	}

	bom := cdx.NewBOM()
	decoder := cdx.NewBOMDecoder(reader, format)
	if err := decoder.Decode(bom); err != nil {
		return nil, format, fmt.Errorf("failed to decode CycloneDX SBOM: %w", err)
	}

	return bom, format, nil
}

// ParseSBOMReader parses a CycloneDX SBOM from any io.Reader.
func ParseSBOMReader(r io.Reader) (*cdx.BOM, cdx.BOMFileFormat, error) {
	format, reader, err := DetectFormat(r)
	if err != nil {
		return nil, cdx.BOMFileFormatJSON, fmt.Errorf("detecting SBOM format: %w", err)
	}

	bom := cdx.NewBOM()
	decoder := cdx.NewBOMDecoder(reader, format)
	if err := decoder.Decode(bom); err != nil {
		return nil, format, fmt.Errorf("failed to decode CycloneDX SBOM: %w", err)
	}

	return bom, format, nil
}

// SaveSBOM safely and atomically saves a CycloneDX SBOM to a file path.
// It verifies that destination is not a symlink, writes to an adjacent temp file, and renames.
func SaveSBOM(bom *cdx.BOM, format cdx.BOMFileFormat, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	// Refuse to overwrite if target is a symlink
	if fi, err := os.Lstat(outputPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write to symlink: %s", outputPath)
		}
	}

	// Create a temporary file in the same directory for atomic rename
	tmpFile, err := os.CreateTemp(dir, ".bomhound-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary file in %s: %w", dir, err)
	}
	tmpName := tmpFile.Name()
	defer func() {
		// Clean up temp file if not renamed
		_ = os.Remove(tmpName)
	}()

	// Encode to temp file
	encoder := cdx.NewBOMEncoder(tmpFile, format)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to encode CycloneDX SBOM: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return fmt.Errorf("syncing temporary file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}

	// Atomic replace
	if err := os.Rename(tmpName, outputPath); err != nil {
		return fmt.Errorf("atomic rename from %s to %s: %w", tmpName, outputPath, err)
	}

	return nil
}

// EncodeSBOM writes the SBOM to the given io.Writer.
func EncodeSBOM(bom *cdx.BOM, format cdx.BOMFileFormat, w io.Writer) error {
	encoder := cdx.NewBOMEncoder(w, format)
	encoder.SetPretty(true)
	return encoder.Encode(bom)
}

// GetPackageType extracts the package type from a PURL using standard packageurl parser.
func GetPackageType(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if trimmed == "" {
		return "unknown"
	}

	p, err := packageurl.FromString(trimmed)
	if err != nil {
		// Fallback check
		if strings.HasPrefix(trimmed, "pkg:") {
			parts := strings.Split(trimmed[4:], "/")
			if len(parts) > 0 && parts[0] != "" {
				return parts[0]
			}
		}
		return "unknown"
	}

	if p.Type == "" {
		return "unknown"
	}
	return p.Type
}

// ToJSONBytes helper serializes a BOM to JSON bytes (useful for testing and debugging).
func ToJSONBytes(bom *cdx.BOM) ([]byte, error) {
	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
