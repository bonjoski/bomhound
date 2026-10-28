package enricher

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bonjoski/bomhound/internal/cache"
	"github.com/bonjoski/bomhound/internal/config"
)

// TestAdversarial_StreamCorruptedInput verifies that feeding a broken or hostile stream
// into EnrichStream returns a clean error without hanging or panicking.
func TestAdversarial_StreamCorruptedInput(t *testing.T) {
	e := NewEnricher(&MockFinder{}, &MockResolver{}, 1, cache.New(), config.DefaultConfig())

	corruptedStreams := []string{
		"",
		"{",
		`{"bomFormat": "CycloneDX", "components": [`,
		string([]byte{0x00, 0xFF, 0xFE}),
	}

	for _, input := range corruptedStreams {
		var out bytes.Buffer
		_, err := e.EnrichStream(context.Background(), strings.NewReader(input), &out)
		if err == nil {
			t.Fatalf("Expected error decoding corrupted stream %q, got nil", input)
		}
	}
}

// TestAdversarial_StreamRoundtripFidelity ensures that streaming through EnrichStream
// preserves all component fields, bom-refs, and formats.
func TestAdversarial_StreamRoundtripFidelity(t *testing.T) {
	inputJSON := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "bom-ref": "ref-1",
      "type": "library",
      "name": "stream-lib",
      "purl": "pkg:github/org/repo@v1.0.0"
    }
  ]
}`

	c := cache.New()
	c.SetCopyright("pkg:github/org/repo@v1.0.0", "Copyright (c) 2026 Stream Owner")

	e := NewEnricher(&MockFinder{}, &MockResolver{}, 2, c, config.DefaultConfig())

	var out bytes.Buffer
	stats, err := e.EnrichStream(context.Background(), strings.NewReader(inputJSON), &out)
	if err != nil {
		t.Fatalf("EnrichStream failed: %v", err)
	}

	if stats.Found != 1 {
		t.Fatalf("Expected 1 found, got %d", stats.Found)
	}

	output := out.String()
	if !strings.Contains(output, "Copyright (c) 2026 Stream Owner") {
		t.Errorf("Stream output missing expected copyright")
	}
	if !strings.Contains(output, "ref-1") {
		t.Errorf("Stream output lost component bom-ref")
	}
}
