package parser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
)

// MaxSBOMSizeBytes caps SBOM input size (file or stream) to 64 MiB to prevent OOM DoS.
const MaxSBOMSizeBytes = 64 << 20

// ErrSBOMTooLarge is returned when an SBOM file or stream exceeds MaxSBOMSizeBytes.
var ErrSBOMTooLarge = fmt.Errorf("SBOM input exceeds maximum allowed size (%d bytes)", MaxSBOMSizeBytes)

type maxBytesReader struct {
	r         io.Reader
	remaining int64
}

func newMaxBytesReader(r io.Reader, limit int64) *maxBytesReader {
	return &maxBytesReader{r: r, remaining: limit}
}

func (m *maxBytesReader) Read(p []byte) (int, error) {
	if m.remaining <= 0 {
		var probe [1]byte
		n, err := m.r.Read(probe[:])
		if n > 0 {
			return 0, ErrSBOMTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > m.remaining {
		p = p[:m.remaining]
	}
	n, err := m.r.Read(p)
	m.remaining -= int64(n)
	return n, err
}

// DetectFormat sniffs the first non-whitespace bytes to determine JSON or XML format.
func DetectFormat(r io.Reader) (cdx.BOMFileFormat, io.Reader, error) {
	br := bufio.NewReader(r)
	for {
		b, err := br.ReadByte()
		if err != nil {
			return cdx.BOMFileFormatJSON, br, fmt.Errorf("reading stream to detect format: %w", err)
		}
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

// ParseSBOM parses a CycloneDX SBOM from a file path while enforcing a 64 MiB size ceiling.
func ParseSBOM(filePath string) (*cdx.BOM, cdx.BOMFileFormat, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, cdx.BOMFileFormatJSON, fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer file.Close()

	if fi, statErr := file.Stat(); statErr == nil && fi.Size() > MaxSBOMSizeBytes {
		return nil, cdx.BOMFileFormatJSON, fmt.Errorf("%w: %s (%d bytes)", ErrSBOMTooLarge, filePath, fi.Size())
	}

	return ParseSBOMReader(file)
}

// ParseSBOMReader parses a CycloneDX SBOM from any io.Reader with a 64 MiB cap.
func ParseSBOMReader(r io.Reader) (*cdx.BOM, cdx.BOMFileFormat, error) {
	bounded := newMaxBytesReader(r, MaxSBOMSizeBytes)
	format, reader, err := DetectFormat(bounded)
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

// SaveSBOM safely and atomically saves a CycloneDX SBOM to a file path,
// rejecting both leaf and parent-directory symlinks.
func SaveSBOM(bom *cdx.BOM, format cdx.BOMFileFormat, outputPath string) error {
	if strings.TrimSpace(outputPath) == "" {
		return errors.New("output path cannot be empty")
	}

	if err := verifyNoSymlinkTraversal(outputPath); err != nil {
		return err
	}

	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	// Re-verify after MkdirAll to defeat TOCTOU parent/leaf symlink swaps.
	if err := verifyNoSymlinkTraversal(outputPath); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, ".bomhound-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary file in %s: %w", dir, err)
	}
	tmpName := tmpFile.Name()
	renamed := false
	defer func() {
		if !renamed {
			if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
				return
			}
		}
	}()

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

	if fi, err := os.Lstat(outputPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write to symlink: %s", outputPath)
	}

	if err := os.Rename(tmpName, outputPath); err != nil {
		return fmt.Errorf("atomic rename from %s to %s: %w", tmpName, outputPath, err)
	}
	renamed = true
	return nil
}

func verifyNoSymlinkTraversal(targetPath string) error {
	cleaned := filepath.Clean(targetPath)

	// Check leaf path itself first
	if fi, err := os.Lstat(cleaned); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write to symlink: %s", targetPath)
	}

	if !filepath.IsAbs(cleaned) {
		parts := strings.Split(cleaned, string(filepath.Separator))
		cur := ""
		for _, p := range parts {
			if p == "" || p == "." {
				continue
			}
			if cur == "" {
				cur = p
			} else {
				cur = cur + string(filepath.Separator) + p
			}
			if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to write to symlink: %s", cur)
			}
		}
		return nil
	}

	// For absolute paths, inspect every component past OS root symlinks (e.g. /var -> /private/var on Darwin).
	relToRoot := strings.TrimPrefix(cleaned, string(filepath.Separator))
	segs := strings.Split(relToRoot, string(filepath.Separator))
	cur := string(filepath.Separator)
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		cur = filepath.Join(cur, seg)
		if i == 0 && (seg == "var" || seg == "tmp" || seg == "etc") {
			continue
		}
		if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write to symlink: %s", cur)
		}
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
