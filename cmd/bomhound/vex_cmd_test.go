package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVEXKernelCLI(t *testing.T) {
	tmpDir := t.TempDir()
	kconfigPath := filepath.Join(tmpDir, ".config")
	kconfigContent := `
CONFIG_64BIT=y
# CONFIG_BT is not set
# CONFIG_USB is not set
# CONFIG_NF_TABLES is not set
`
	if err := os.WriteFile(kconfigPath, []byte(kconfigContent), 0600); err != nil {
		t.Fatalf("failed to write dummy .config: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "out.vex.json")

	code := runVEX([]string{"kernel", "--kconfig", kconfigPath, "--output", outputPath})
	if code != 0 {
		t.Fatalf("expected runVEX to return 0, got %d", code)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("failed to read output VEX file: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("output VEX file is empty")
	}
}
