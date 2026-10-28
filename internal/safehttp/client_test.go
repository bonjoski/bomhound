package safehttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func resetLookupIP() {
	lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, network, host)
	}
}

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		// Nil/empty check
		{"nil IP", "", true},

		// Loopback
		{"IPv4 Loopback 127.0.0.1", "127.0.0.1", true},
		{"IPv4 Loopback 127.255.255.254", "127.255.255.254", true},
		{"IPv6 Loopback ::1", "::1", true},

		// Private IPv4 ranges
		{"Private 10.0.0.1", "10.0.0.1", true},
		{"Private 10.254.1.2", "10.254.1.2", true},
		{"Private 172.16.0.1", "172.16.0.1", true},
		{"Private 172.31.255.255", "172.31.255.255", true},
		{"Private 192.168.0.1", "192.168.0.1", true},
		{"Private 192.168.254.254", "192.168.254.254", true},

		// Link-Local and Cloud Metadata
		{"Link-Local 169.254.1.1", "169.254.1.1", true},
		{"Cloud Metadata 169.254.169.254", "169.254.169.254", true},
		{"IPv6 Link-Local fe80::1", "fe80::1", true},

		// Multicast
		{"IPv4 Multicast 224.0.0.1", "224.0.0.1", true},
		{"IPv4 Multicast 239.255.255.250", "239.255.255.250", true},
		{"IPv6 Multicast ff02::1", "ff02::1", true},

		// Unspecified / current network
		{"IPv4 Unspecified 0.0.0.0", "0.0.0.0", true},
		{"IPv6 Unspecified ::", "::", true},

		// IPv6 Unique Local Address
		{"IPv6 ULA fc00::1", "fc00::1", true},
		{"IPv6 ULA fd12:3456:789a::1", "fd12:3456:789a::1", true},

		// IPv4-mapped IPv6
		{"IPv4-mapped Loopback ::ffff:127.0.0.1", "::ffff:127.0.0.1", true},
		{"IPv4-mapped Metadata ::ffff:169.254.169.254", "::ffff:169.254.169.254", true},
		{"IPv4-mapped Private ::ffff:10.0.0.1", "::ffff:10.0.0.1", true},

		// Public Safe IPs
		{"Cloudflare DNS 1.1.1.1", "1.1.1.1", false},
		{"Google DNS 8.8.8.8", "8.8.8.8", false},
		{"Public IP 93.184.216.34", "93.184.216.34", false},
		{"Public IPv6 2606:4700:4700::1111", "2606:4700:4700::1111", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ip net.IP
			if tc.ip != "" {
				ip = net.ParseIP(tc.ip)
				if ip == nil {
					t.Fatalf("failed to parse IP %s", tc.ip)
				}
			}
			got := IsBlockedIP(ip)
			if got != tc.blocked {
				t.Errorf("IsBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}

func TestSafeControl(t *testing.T) {
	// Blocked address
	err := SafeControl("tcp", "127.0.0.1:80", nil)
	if !errors.Is(err, ErrBlockedIP) {
		t.Fatalf("expected ErrBlockedIP for 127.0.0.1, got: %v", err)
	}

	// Blocked IPv6 address
	err = SafeControl("tcp", "[::1]:443", nil)
	if !errors.Is(err, ErrBlockedIP) {
		t.Fatalf("expected ErrBlockedIP for [::1], got: %v", err)
	}

	// Blocked Cloud Metadata
	err = SafeControl("tcp", "169.254.169.254:80", nil)
	if !errors.Is(err, ErrBlockedIP) {
		t.Fatalf("expected ErrBlockedIP for cloud metadata, got: %v", err)
	}

	// Safe Public IP
	err = SafeControl("tcp", "93.184.216.34:443", nil)
	if err != nil {
		t.Fatalf("expected nil error for safe public IP, got: %v", err)
	}

	// Invalid format
	err = SafeControl("tcp", "not-an-ip-or-port", nil)
	if err == nil {
		t.Fatal("expected error for invalid address format, got nil")
	}
}

func TestSafeDialContext_BlockedIPs(t *testing.T) {
	ctx := context.Background()

	// Direct IP literal
	_, err := SafeDialContext(ctx, "tcp", "127.0.0.1:8080")
	if !errors.Is(err, ErrBlockedIP) {
		t.Fatalf("expected ErrBlockedIP for 127.0.0.1, got: %v", err)
	}

	_, err = SafeDialContext(ctx, "tcp", "169.254.169.254:80")
	if !errors.Is(err, ErrBlockedIP) {
		t.Fatalf("expected ErrBlockedIP for 169.254.169.254, got: %v", err)
	}

	// Host resolving to blocked IP
	defer resetLookupIP()
	lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.5")}, nil
	}

	_, err = SafeDialContext(ctx, "tcp", "internal.corp.local:80")
	if !errors.Is(err, ErrBlockedIP) {
		t.Fatalf("expected ErrBlockedIP for host resolving to 10.0.0.5, got: %v", err)
	}
}

func TestSafeDialContext_LookupErrors(t *testing.T) {
	ctx := context.Background()
	defer resetLookupIP()

	// Lookup returns error
	lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		return nil, errors.New("dns failure")
	}

	_, err := SafeDialContext(ctx, "tcp", "unknown.example:80")
	if err == nil {
		t.Fatal("expected DNS error, got nil")
	}

	// Lookup returns no IPs
	lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		return []net.IP{}, nil
	}

	_, err = SafeDialContext(ctx, "tcp", "empty.example:80")
	if err == nil {
		t.Fatal("expected error for empty resolved IPs, got nil")
	}
}

func TestCheckRedirect(t *testing.T) {
	defer resetLookupIP()
	lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		if host == "safe.example.com" {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		if host == "evil.example.com" {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return nil, errors.New("unknown host")
	}

	t.Run("stops after 3 redirects", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://safe.example.com/step4", nil)
		via := []*http.Request{
			{URL: &url.URL{Scheme: "https", Host: "safe.example.com", Path: "/step1"}},
			{URL: &url.URL{Scheme: "https", Host: "safe.example.com", Path: "/step2"}},
			{URL: &url.URL{Scheme: "https", Host: "safe.example.com", Path: "/step3"}},
		}
		err := CheckRedirect(req, via)
		if !errors.Is(err, ErrTooManyRedirects) {
			t.Fatalf("expected ErrTooManyRedirects, got: %v", err)
		}
	})

	t.Run("allows fewer than 3 redirects", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://safe.example.com/step3", nil)
		via := []*http.Request{
			{URL: &url.URL{Scheme: "https", Host: "safe.example.com", Path: "/step1"}},
			{URL: &url.URL{Scheme: "https", Host: "safe.example.com", Path: "/step2"}},
		}
		err := CheckRedirect(req, via)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
	})

	t.Run("prohibits non-HTTPS schemes", func(t *testing.T) {
		schemes := []string{"http://safe.example.com", "ftp://safe.example.com", "file:///etc/passwd"}
		for _, rawURL := range schemes {
			parsed, _ := url.Parse(rawURL)
			req := &http.Request{URL: parsed}
			err := CheckRedirect(req, nil)
			if !errors.Is(err, ErrInsecureRedirectScheme) {
				t.Fatalf("expected ErrInsecureRedirectScheme for %s, got: %v", rawURL, err)
			}
		}
	})

	t.Run("validates redirect IP literal - blocked", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://127.0.0.1/admin", nil)
		err := CheckRedirect(req, nil)
		if !errors.Is(err, ErrBlockedIP) {
			t.Fatalf("expected ErrBlockedIP for redirect to 127.0.0.1, got: %v", err)
		}
	})

	t.Run("validates redirect hostname - blocked", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://evil.example.com/steal", nil)
		err := CheckRedirect(req, nil)
		if !errors.Is(err, ErrBlockedIP) {
			t.Fatalf("expected ErrBlockedIP for evil.example.com, got: %v", err)
		}
	})

	t.Run("validates redirect hostname - safe", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://safe.example.com/ok", nil)
		err := CheckRedirect(req, nil)
		if err != nil {
			t.Fatalf("expected no error for safe.example.com, got: %v", err)
		}
	})
}

func TestNewSafeHTTPClient_BlocksLoopbackServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewSafeHTTPClient(2 * time.Second)

	// Since httptest.Server listens on 127.0.0.1, SafeHTTPClient must block the request
	_, err := client.Get(ts.URL)
	if err == nil {
		t.Fatal("expected request to local httptest server to be blocked, but it succeeded")
	}
	if !errors.Is(err, ErrBlockedIP) {
		t.Fatalf("expected ErrBlockedIP, got: %v", err)
	}
}

func TestNewSafeHTTPClient_Configuration(t *testing.T) {
	client := NewSafeHTTPClient(5 * time.Second)
	if client.Timeout != 5*time.Second {
		t.Errorf("expected client timeout 5s, got: %v", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Error("expected client.CheckRedirect to be set")
	}
	if client.Transport == nil {
		t.Error("expected client.Transport to be set")
	}
}
