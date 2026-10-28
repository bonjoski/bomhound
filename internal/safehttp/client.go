package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

var (
	// ErrBlockedIP is returned when an address resolves to a restricted/private/loopback IP.
	ErrBlockedIP = errors.New("access to blocked IP address denied")
	// ErrTooManyRedirects is returned when exceeding the 3-redirect limit.
	ErrTooManyRedirects = errors.New("stopped after 3 redirects")
	// ErrInsecureRedirectScheme is returned when redirecting to a non-HTTPS scheme.
	ErrInsecureRedirectScheme = errors.New("redirect to non-HTTPS scheme prohibited")
)

var blockedCIDRs = []*net.IPNet{
	mustParseCIDR("127.0.0.0/8"),    // IPv4 Loopback
	mustParseCIDR("::1/128"),        // IPv6 Loopback
	mustParseCIDR("10.0.0.0/8"),     // IPv4 Private (RFC 1918)
	mustParseCIDR("172.16.0.0/12"),  // IPv4 Private (RFC 1918)
	mustParseCIDR("192.168.0.0/16"), // IPv4 Private (RFC 1918)
	mustParseCIDR("169.254.0.0/16"), // IPv4 Link-Local & Cloud Metadata (RFC 3927)
	mustParseCIDR("fe80::/10"),      // IPv6 Link-Local
	mustParseCIDR("224.0.0.0/4"),    // IPv4 Multicast
	mustParseCIDR("ff00::/8"),       // IPv6 Multicast
	mustParseCIDR("0.0.0.0/8"),      // IPv4 "This" Network
	mustParseCIDR("::/128"),         // IPv6 Unspecified
	mustParseCIDR("fc00::/7"),       // IPv6 Unique Local Address (ULA)
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR %s: %v", s, err))
	}
	return ipNet
}

// lookupIP can be overridden in tests.
var lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

// IsBlockedIP returns true if the IP falls within loopback, private, link-local,
// cloud metadata, or multicast ranges.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Canonicalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// SafeControl is a net.Dialer Control function that checks if the socket's
// destination IP address is blocked before establishing the connection.
func SafeControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid destination address %q: %w", address, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid destination IP %q", host)
	}

	if IsBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedIP, ip)
	}

	return nil
}

// NewSafeDialer creates a net.Dialer configured with SafeControl and standard timeouts.
func NewSafeDialer(timeout time.Duration) *net.Dialer {
	dialTimeout := timeout
	if dialTimeout <= 0 {
		dialTimeout = 30 * time.Second
	}
	return &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		Control:   SafeControl,
	}
}

// SafeDialContext resolves the host, verifies that all resolved IP addresses are safe,
// and dials using a safe net.Dialer.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := NewSafeDialer(30 * time.Second)
	return SafeDialContextWithDialer(ctx, network, addr, dialer)
}

// SafeDialContextWithDialer performs pre-dial IP verification and then invokes dialer.DialContext.
func SafeDialContextWithDialer(ctx context.Context, network, addr string, dialer *net.Dialer) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedIP, ip)
		}
	} else {
		ips, err := lookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve host %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses resolved for host %q", host)
		}
		for _, ip := range ips {
			if IsBlockedIP(ip) {
				return nil, fmt.Errorf("%w: host %q resolved to blocked IP %s", ErrBlockedIP, host, ip)
			}
		}
	}

	return dialer.DialContext(ctx, network, addr)
}

// CheckRedirect enforces:
// 1. Up to 3 redirects maximum (stops when len(via) >= 3)
// 2. Prohibits redirecting to non-HTTPS schemes
// 3. Validates redirect destination IPs against the safe IP filter
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return ErrTooManyRedirects
	}

	if req.URL == nil || !strings.EqualFold(req.URL.Scheme, "https") {
		scheme := ""
		if req.URL != nil {
			scheme = req.URL.Scheme
		}
		return fmt.Errorf("%w: scheme %q", ErrInsecureRedirectScheme, scheme)
	}

	host := req.URL.Hostname()
	if host == "" {
		return fmt.Errorf("redirect URL has empty host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedIP, ip)
		}
	} else {
		ctx := req.Context()
		ips, err := lookupIP(ctx, "ip", host)
		if err != nil {
			return fmt.Errorf("failed to resolve redirect host %q: %w", host, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IP addresses resolved for redirect host %q", host)
		}
		for _, ip := range ips {
			if IsBlockedIP(ip) {
				return fmt.Errorf("%w: redirect host %q resolved to blocked IP %s", ErrBlockedIP, host, ip)
			}
		}
	}

	return nil
}

// NewSafeHTTPClient returns an *http.Client configured with SSRF protection,
// safe dialer/transport, and secure redirect handling.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := NewSafeDialer(timeout)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return SafeDialContextWithDialer(ctx, network, addr, dialer)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: CheckRedirect,
	}
}
