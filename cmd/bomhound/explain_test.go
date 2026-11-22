package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bonjoski/bomhound/pkg/ux"
)

func TestBomhoundExplain_AllTopicsAndFlags(t *testing.T) {
	topics := []string{"attribution", "cyclonedx", "apache-4c", "dmca-1202", "sbom"}

	for _, topic := range topics {
		t.Run(topic+"/default", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q) exit=%d stderr=%s", topic, code, errBuf.String())
			}
			rendered := out.String()
			if strings.ContainsRune(rendered, 0x1b) {
				t.Fatalf("explain output contains raw ESC: %q", rendered)
			}
			lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
			if len(lines) > 3 {
				t.Fatalf("default explain(%q) exceeded 3 lines (%d):\n%s", topic, len(lines), rendered)
			}
		})

		t.Run(topic+"/why", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic, "--why"}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q, --why) exit=%d", topic, code)
			}
			if !strings.Contains(out.String(), "Deep Dive (--why):") {
				t.Fatalf("expected Deep Dive (--why) for %q", topic)
			}
		})

		t.Run(topic+"/json", func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runExplain([]string{topic, "--json"}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("runExplain(%q, --json) exit=%d", topic, code)
			}
			var decoded ux.FixForwardError
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
				t.Fatalf("invalid JSON for %q: %v", topic, err)
			}
			if decoded.Tool != "bomhound" || decoded.Code == "" || decoded.Summary == "" || decoded.RemediationCmd == "" || decoded.WhyOneLiner == "" {
				t.Fatalf("incomplete FixForwardError JSON for %q: %+v", topic, decoded)
			}
		})
	}
}

func TestBomhoundExplain_DefaultAndUnknownTopic(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := runExplain([]string{"--json"}, &out, &errBuf); code != 0 {
		t.Fatalf("expected default explain --json exit 0, got %d", code)
	}
	var def ux.FixForwardError
	if err := json.Unmarshal(out.Bytes(), &def); err != nil {
		t.Fatalf("default explain JSON invalid: %v", err)
	}
	if def.Code != "BOMHOUND_EXPLAIN_ATTRIBUTION" {
		t.Fatalf("expected BOMHOUND_EXPLAIN_ATTRIBUTION, got %q", def.Code)
	}

	out.Reset()
	errBuf.Reset()
	if code := runExplain([]string{"bogus-topic", "--json"}, &out, &errBuf); code != 1 {
		t.Fatalf("expected unknown topic exit 1, got %d", code)
	}
	var unk ux.FixForwardError
	if err := json.Unmarshal(errBuf.Bytes(), &unk); err != nil {
		t.Fatalf("unknown topic stderr JSON invalid: %v", err)
	}
	if unk.Code != "BOMHOUND_EXPLAIN_UNKNOWN_TOPIC" || unk.RemediationCmd == "" || unk.WhyOneLiner == "" {
		t.Fatalf("unexpected FixForwardError: %+v", unk)
	}
}
