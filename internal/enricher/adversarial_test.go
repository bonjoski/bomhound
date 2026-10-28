package enricher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bonjoski/bomhound/internal/cache"
	"github.com/bonjoski/bomhound/internal/config"
	"github.com/bonjoski/bomhound/internal/copyright"
	"github.com/bonjoski/bomhound/internal/parser"
)

// AdversarialFinder simulates network anomalies, slow calls, and circuit-breaker conditions
type AdversarialFinder struct {
	callCount     int64
	failOnCount   int64
	returnedError error
	delay         time.Duration
}

func (a *AdversarialFinder) FindCopyright(ctx context.Context, purl string) (string, error) {
	notices, err := a.FindCopyrights(ctx, purl)
	if err != nil {
		return "", err
	}
	if len(notices) > 0 {
		return notices[0], nil
	}
	return "", nil
}

func (a *AdversarialFinder) FindCopyrights(ctx context.Context, purl string) ([]string, error) {
	current := atomic.AddInt64(&a.callCount, 1)
	if a.delay > 0 {
		select {
		case <-time.After(a.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if a.failOnCount > 0 && current >= a.failOnCount && a.returnedError != nil {
		return nil, a.returnedError
	}

	return []string{"Copyright (c) 2026 Adversarial Owner"}, nil
}

// TestAdversarial_ContextCancellationUnderHeavyLoad verifies that when a context is cancelled
// (e.g. SIGINT/SIGTERM), all workers cleanly and immediately abort without deadlocking or leaking.
func TestAdversarial_ContextCancellationUnderHeavyLoad(t *testing.T) {
	// Create a synthetic SBOM with 500 components
	bom := cdx.NewBOM()
	var components []cdx.Component
	for i := 0; i < 500; i++ {
		components = append(components, cdx.Component{
			Name:       fmt.Sprintf("component-%d", i),
			PackageURL: fmt.Sprintf("pkg:golang/github.com/test/repo-%d@v1.0.0", i),
			Type:       "library",
		})
	}
	bom.Components = &components

	tmpInput, err := os.CreateTemp("", "adv-cancel-in-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp input: %v", err)
	}
	defer os.Remove(tmpInput.Name())
	if err := parser.SaveSBOM(bom, cdx.BOMFileFormatJSON, tmpInput.Name()); err != nil {
		t.Fatalf("Failed to write temp input: %v", err)
	}

	tmpOutput, err := os.CreateTemp("", "adv-cancel-out-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp output: %v", err)
	}
	outputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputPath)

	finder := &AdversarialFinder{
		delay: 10 * time.Millisecond, // slow down processing
	}
	resolver := &MockResolver{results: make(map[string]string)}
	c := cache.New()
	e := NewEnricher(finder, resolver, 10, c, config.DefaultConfig())

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context shortly after dispatching
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err = e.Enrich(ctx, tmpInput.Name(), outputPath)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Expected context cancellation error, got nil")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}

	// Must terminate promptly (under 200ms) despite 500 slow components
	if elapsed > 300*time.Millisecond {
		t.Errorf("Context cancellation took too long: %v", elapsed)
	}
}

// TestAdversarial_CircuitBreakerErrorPropagation verifies that when GitHub rate limit
// is tripped, errors are not swallowed and are recorded in stats.
func TestAdversarial_CircuitBreakerErrorPropagation(t *testing.T) {
	bom := cdx.NewBOM()
	components := []cdx.Component{
		{Name: "c1", PackageURL: "pkg:golang/github.com/test/r1@v1.0.0", Type: "library"},
		{Name: "c2", PackageURL: "pkg:golang/github.com/test/r2@v1.0.0", Type: "library"},
	}
	bom.Components = &components

	tmpInput, err := os.CreateTemp("", "adv-cb-in-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp: %v", err)
	}
	defer os.Remove(tmpInput.Name())
	parser.SaveSBOM(bom, cdx.BOMFileFormatJSON, tmpInput.Name())

	tmpOutput, err := os.CreateTemp("", "adv-cb-out-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp: %v", err)
	}
	outputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer os.Remove(outputPath)

	finder := &AdversarialFinder{
		failOnCount:   1,
		returnedError: copyright.ErrRateLimitExceeded,
	}
	resolver := &MockResolver{results: make(map[string]string)}
	c := cache.New()
	e := NewEnricher(finder, resolver, 1, c, config.DefaultConfig())

	stats, err := e.Enrich(context.Background(), tmpInput.Name(), outputPath)
	if err != nil {
		t.Fatalf("Enrich returned unexpected fatal error: %v", err)
	}

	if stats.FailedCopyright == 0 {
		t.Errorf("Expected FailedCopyright to reflect rate limit error, got: %d", stats.FailedCopyright)
	}
}
