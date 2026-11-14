// Package vex provides kernel reachability analysis and OpenVEX / CSAF statement
// generation for minimal microVM guest kernels and embedded Linux environments.
package vex

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// KconfigMap represents parsed key-value pairs from a Linux kernel .config file.
type KconfigMap map[string]string

// ParseKconfig reads and parses a standard Linux Kconfig file (.config).
func ParseKconfig(r io.Reader) (KconfigMap, error) {
	scanner := bufio.NewScanner(r)
	config := make(KconfigMap)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Handle comments and un-set symbols: "# CONFIG_FOO is not set"
		if strings.HasPrefix(line, "#") {
			if strings.Contains(line, "is not set") {
				parts := strings.Fields(line)
				if len(parts) >= 2 && strings.HasPrefix(parts[1], "CONFIG_") {
					config[parts[1]] = "n"
				}
			}
			continue
		}

		// Handle set symbols: "CONFIG_FOO=y", "CONFIG_BAR=m", "CONFIG_STR=\"val\""
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			config[key] = val
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return config, nil
}

// ParseKconfigFile reads a .config file directly from disk.
func ParseKconfigFile(path string) (KconfigMap, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ParseKconfig(f)
}

// IsEnabled returns true if the Kconfig option is enabled as built-in ('y') or module ('m').
func (k KconfigMap) IsEnabled(key string) bool {
	val := k[key]
	return val == "y" || val == "m"
}
