package bomhound

import (
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	if Version != "0.1.4" && Version != "v0.1.4" {
		t.Errorf("Unexpected Version: %s", Version)
	}

	formatted := FormattedVersion()
	if !strings.HasPrefix(formatted, "v0.1.4") {
		t.Errorf("Expected FormattedVersion to start with v0.1.4, got: %s", formatted)
	}

	// Test with metadata
	origCommit, origDate := GitCommit, BuildDate
	defer func() {
		GitCommit, BuildDate = origCommit, origDate
	}()

	GitCommit = "abc1234"
	BuildDate = "2026-10-28"
	withMeta := FormattedVersion()
	if withMeta != "v0.1.4 (abc1234, 2026-10-28)" {
		t.Errorf("Unexpected FormattedVersion with metadata: %s", withMeta)
	}

	BuildDate = "unknown"
	onlyCommit := FormattedVersion()
	if onlyCommit != "v0.1.4 (abc1234)" {
		t.Errorf("Unexpected FormattedVersion with commit only: %s", onlyCommit)
	}
}
