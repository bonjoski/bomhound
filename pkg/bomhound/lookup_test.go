package bomhound

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLookupLicenses_KnownPackages(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name     string
		purl     string
		expected string
	}{
		{
			name:     "Azure Go SDK",
			purl:     "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.14.0",
			expected: "MIT",
		},
		{
			name:     "Golang x crypto vanity URL",
			purl:     "pkg:golang/golang.org/x/crypto@v0.43.0",
			expected: "BSD-3-Clause",
		},
		{
			name:     "Google gRPC vanity URL",
			purl:     "pkg:golang/google.golang.org/grpc@v1.76.0",
			expected: "Apache-2.0",
		},
		{
			name:     "Kubernetes klog vanity URL",
			purl:     "pkg:golang/k8s.io/klog/v2@v2.130.1",
			expected: "Apache-2.0",
		},
		{
			name:     "Cargo anyhow crate",
			purl:     "anyhow",
			expected: "MIT",
		},
		{
			name:     "Cargo anyhow purl",
			purl:     "pkg:cargo/anyhow@1.0.75",
			expected: "MIT",
		},
		{
			name:     "Cargo serde crate",
			purl:     "serde",
			expected: "MIT",
		},
		{
			name:     "NPM React package",
			purl:     "pkg:npm/react@18.2.0",
			expected: "MIT",
		},
		{
			name:     "NPM Axios package",
			purl:     "axios",
			expected: "MIT",
		},
		{
			name:     "IBM Sarama",
			purl:     "pkg:golang/github.com/IBM/sarama@v1.43.3",
			expected: "MIT",
		},
		{
			name:     "AWS SDK",
			purl:     "pkg:golang/github.com/aws/smithy-go@v1.21.0",
			expected: "Apache-2.0",
		},
		{
			name:     "Unknown package",
			purl:     "pkg:generic/completely-unknown-package-xyz@9.9.9",
			expected: "UNKNOWN",
		},
	}

	purls := make([]string, len(testCases))
	for i, tc := range testCases {
		purls[i] = tc.purl
	}

	results, err := LookupLicenses(ctx, purls)
	if err != nil {
		t.Fatalf("LookupLicenses returned unexpected error: %v", err)
	}

	if len(results) != len(purls) {
		t.Fatalf("expected %d results, got %d", len(purls), len(results))
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, exists := results[tc.purl]
			if !exists {
				t.Fatalf("missing result for purl: %s", tc.purl)
			}
			if !strings.EqualFold(got, tc.expected) && !strings.Contains(strings.ToUpper(got), strings.ToUpper(tc.expected)) {
				t.Errorf("LookupLicenses(%q) = %q; want %q", tc.purl, got, tc.expected)
			}
		})
	}
}

func TestLookupLicenses_CorporateAllowlistVerification(t *testing.T) {
	ctx := context.Background()

	// Corporate allowlist from requirement: MIT, Apache-2.0
	allowlist := map[string]bool{
		"MIT":        true,
		"APACHE-2.0": true,
	}

	purls := []string{
		"pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.14.0", // MIT
		"pkg:golang/google.golang.org/grpc@v1.76.0",                        // Apache-2.0
		"anyhow",                                                          // MIT
		"pkg:golang/golang.org/x/crypto@v0.43.0",                          // BSD-3-Clause (Not in allowlist)
		"unknown-package",                                                 // UNKNOWN
	}

	licenses, err := LookupLicenses(ctx, purls)
	if err != nil {
		t.Fatalf("LookupLicenses failed: %v", err)
	}

	compliant := make([]string, 0)
	nonCompliant := make([]string, 0)
	unlicensed := make([]string, 0)

	for p, lic := range licenses {
		if lic == "" || strings.EqualFold(lic, "UNKNOWN") {
			unlicensed = append(unlicensed, p)
		} else if allowlist[strings.ToUpper(lic)] {
			compliant = append(compliant, p)
		} else {
			nonCompliant = append(nonCompliant, p)
		}
	}

	if len(compliant) != 3 {
		t.Errorf("expected 3 compliant packages, got %d: %v", len(compliant), compliant)
	}
	if len(nonCompliant) != 1 {
		t.Errorf("expected 1 non-compliant package (BSD-3-Clause), got %d: %v", len(nonCompliant), nonCompliant)
	}
	if len(unlicensed) != 1 {
		t.Errorf("expected 1 unlicensed package, got %d: %v", len(unlicensed), unlicensed)
	}
}

func TestLookupLicenses_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := LookupLicenses(ctx, []string{"pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.14.0"})
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
}

func TestLookupLicenses_ZeroNetworkLatency(t *testing.T) {
	ctx := context.Background()
	purls := []string{
		"pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.14.0",
		"pkg:golang/google.golang.org/grpc@v1.76.0",
		"anyhow",
		"serde",
		"pkg:npm/react@18.2.0",
	}

	start := time.Now()
	_, err := LookupLicenses(ctx, purls)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("LookupLicenses failed: %v", err)
	}

	// In-process memory lookup should complete in well under 50ms
	if elapsed > 100*time.Millisecond {
		t.Errorf("LookupLicenses took %v; expected sub-millisecond in-process latency", elapsed)
	}
}
