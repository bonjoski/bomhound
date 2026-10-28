package utils

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// FindSBOMFiles returns a list of .json files in the given path (file or directory).
// It searches recursively and excludes hidden directories and output directories.
func FindSBOMFiles(root string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			name := d.Name()
			// Skip hidden directories and output directories
			if strings.HasPrefix(name, ".") && name != "." {
				return filepath.SkipDir
			}
			if strings.HasPrefix(name, "output") {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip cache files
		if strings.HasPrefix(d.Name(), ".sbom-cache") {
			return nil
		}

		if strings.HasSuffix(d.Name(), ".json") {
			files = append(files, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	return files, nil
}
