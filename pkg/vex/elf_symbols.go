package vex

import (
	"bufio"
	"debug/elf"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractELFSymbols extracts all function and object symbol names from an ELF vmlinux binary.
// It inspects both static (.symtab) and dynamic (.dynsym) symbol tables.
func ExtractELFSymbols(path string) (map[string]bool, error) {
	cleanPath := filepath.Clean(path)
	f, err := elf.Open(cleanPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	symbols := make(map[string]bool)

	// Attempt reading static symbols (.symtab)
	syms, err := f.Symbols()
	if err == nil {
		for _, s := range syms {
			if s.Name != "" {
				symbols[s.Name] = true
			}
		}
	}

	// Attempt reading dynamic symbols (.dynsym)
	dynsyms, err := f.DynamicSymbols()
	if err == nil {
		for _, s := range dynsyms {
			if s.Name != "" {
				symbols[s.Name] = true
			}
		}
	}

	return symbols, nil
}

// ParseKallsyms parses a /proc/kallsyms or dumped symbol text stream.
// Lines format: <address> <type> <name> [<module>]
func ParseKallsyms(r io.Reader) (map[string]bool, error) {
	scanner := bufio.NewScanner(r)
	symbols := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 3 {
			symName := fields[2]
			symbols[symName] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return symbols, nil
}

// ParseKallsymsFile reads a kallsyms file directly from disk.
func ParseKallsymsFile(path string) (map[string]bool, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return ParseKallsyms(f)
}
