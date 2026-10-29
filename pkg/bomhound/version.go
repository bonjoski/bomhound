package bomhound

import (
	"fmt"
	"strings"
)

// Version is the single source of truth for bomhound's semantic release version.
var Version = "0.1.2"

// GitCommit and BuildDate can be optionally populated at build time via -ldflags.
var (
	GitCommit = "none"
	BuildDate = "unknown"
)

// FormattedVersion returns the version with 'v' prefix and optional build metadata.
func FormattedVersion() string {
	ver := Version
	if !strings.HasPrefix(ver, "v") {
		ver = "v" + ver
	}

	if GitCommit != "none" && GitCommit != "" {
		if BuildDate != "unknown" && BuildDate != "" {
			return fmt.Sprintf("%s (%s, %s)", ver, GitCommit, BuildDate)
		}
		return fmt.Sprintf("%s (%s)", ver, GitCommit)
	}
	return ver
}
