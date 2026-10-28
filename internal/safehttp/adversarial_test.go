package safehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestAdversarial_DNSRebindingSocketControl verifies that even if DNS lookup initially succeeds,
// SafeControl blocks the socket connection at raw socket creation if the destination IP is forbidden.
func TestAdversarial_DNSRebindingSocketControl(t *testing.T) {
	blockedAddresses := []string{
		"127.0.0.1:80",
		"169.254.169.254:80",
		"10.0.0.1:443",
		"192.168.1.1:8080",
		"[::1]:80",
		"[fe80::1]:80",
	}

	for _, addr := range blockedAddresses {
		t.Run(addr, func(t *testing.T) {
			err := SafeControl("tcp", addr, nil)
			if err == nil {
				t.Fatalf("SafeControl permitted blocked address: %s", addr)
			}
			if !strings.Contains(err.Error(), "blocked IP address denied") {
				t.Errorf("Unexpected error message: %v", err)
			}
		})
	}
}

// TestAdversarial_RedirectChainsAndDowngrades tests multi-hop redirect attacks:
// 1. Redirect loop
// 2. Redirect hopping to private IP
// 3. HTTPS to HTTP downgrade
func TestAdversarial_RedirectChainsAndDowngrades(t *testing.T) {
	client := NewSafeHTTPClient(3 * time.Second)

	// Sub-test 1: HTTPS to HTTP downgrade attempt
	t.Run("HTTPS_to_HTTP_downgrade", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com/insecure", nil)
		via := []*http.Request{
			{URL: req.URL},
		}
		err := client.CheckRedirect(req, via)
		if err == nil || !strings.Contains(err.Error(), "non-HTTPS scheme prohibited") {
			t.Fatalf("Expected non-HTTPS scheme prohibited error, got: %v", err)
		}
	})

	// Sub-test 2: Infinite redirect loop (> 3 hops)
	t.Run("redirect_depth_exceeded", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://example.com/hop4", nil)
		via := []*http.Request{
			{URL: req.URL},
			{URL: req.URL},
			{URL: req.URL},
		}
		err := client.CheckRedirect(req, via)
		if err != ErrTooManyRedirects {
			t.Fatalf("Expected ErrTooManyRedirects, got: %v", err)
		}
	})

	// Sub-test 3: Redirect to cloud metadata IP
	t.Run("redirect_to_cloud_metadata", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://169.254.169.254/latest/meta-data", nil)
		via := []*http.Request{
			{URL: req.URL},
		}
		err := client.CheckRedirect(req, via)
		if err == nil || !strings.Contains(err.Error(), "access to blocked IP address denied") {
			t.Fatalf("Expected blocked IP error on redirect, got: %v", err)
		}
	})
}

// TestAdversarial_SafeDialContext_Timeout verifies that unreachable hosts
// timeout quickly without hanging the process or holding goroutines open.
func TestAdversarial_SafeDialContext_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// 192.0.2.1 is TEST-NET-1 (non-routable documentation IP, will hang without timeout)
	start := time.Now()
	_, err := SafeDialContext(ctx, "tcp", "192.0.2.1:80")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Expected timeout error dialing TEST-NET-1")
	}

	if elapsed > 1*time.Second {
		t.Fatalf("DialContext took too long to abort on cancelled context: %v", elapsed)
	}
}

// TestAdversarial_LoopbackServerBlocked verifies live execution against local HTTP test server
func TestAdversarial_LoopbackServerBlocked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SHOULD_NEVER_BE_REACHED"))
	}))
	defer ts.Close()

	client := NewSafeHTTPClient(2 * time.Second)
	_, err := client.Get(ts.URL)
	if err == nil {
		t.Fatalf("Adversarial attack succeeded: SafeHTTPClient connected to localhost server!")
	}

	if !strings.Contains(err.Error(), "access to blocked IP address denied") {
		t.Errorf("Unexpected error: %v", err)
	}
}
