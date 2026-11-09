package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // IPv4 "This" network (RFC 1122)
	netip.MustParsePrefix("10.0.0.0/8"),     // IPv4 Private (RFC 1918)
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT / Tailscale / Alibaba Cloud IMDS (RFC 6598)
	netip.MustParsePrefix("127.0.0.0/8"),    // IPv4 Loopback
	netip.MustParsePrefix("169.254.0.0/16"), // IPv4 Link-Local & Cloud Metadata (RFC 3927)
	netip.MustParsePrefix("172.16.0.0/12"),  // IPv4 Private (RFC 1918)
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF Protocol Assignments
	netip.MustParsePrefix("192.168.0.0/16"), // IPv4 Private (RFC 1918)
	netip.MustParsePrefix("198.18.0.0/15"),  // Network Interconnect Device Benchmarking (RFC 2544)
	netip.MustParsePrefix("224.0.0.0/4"),    // IPv4 Multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // IPv4 Reserved / Limited Broadcast
	netip.MustParsePrefix("::/128"),         // IPv6 Unspecified
	netip.MustParsePrefix("::1/128"),        // IPv6 Loopback
	netip.MustParsePrefix("64:ff9b::/96"),   // IPv4/IPv6 NAT64 Translation (RFC 6052)
	netip.MustParsePrefix("64:ff9b:1::/48"), // Local-Use NAT64 (RFC 8215)
	netip.MustParsePrefix("100::/64"),       // IPv6 Discard-Only Prefix (RFC 6666)
	netip.MustParsePrefix("2001::/32"),      // Teredo Tunneling (RFC 4380)
	netip.MustParsePrefix("2002::/16"),      // 6to4 Tunneling (RFC 3056)
	netip.MustParsePrefix("fc00::/7"),       // IPv6 Unique Local Address (ULA, RFC 4193)
	netip.MustParsePrefix("fe80::/10"),      // IPv6 Link-Local
	netip.MustParsePrefix("ff00::/8"),       // IPv6 Multicast
}

// lookupIP can be overridden in tests.
var lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

// IsBlockedAddr returns true if the netip.Addr is invalid, non-global-unicast, loopback,
// private, link-local, multicast, CGNAT/IMDS, benchmarking, or in an IPv6 transition range.
func IsBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()

	if !addr.IsGlobalUnicast() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return true
	}

	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// IsBlockedIP returns true if the IP falls within loopback, private, link-local,
// cloud metadata, CGNAT, NAT64/6to4/Teredo, or multicast ranges.
func IsBlockedIP(ip net.IP) bool {
	if len(ip) == 0 {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return IsBlockedAddr(addr)
}

func parseHostAddr(host string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, true
	}
	if ip := net.ParseIP(host); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// SafeControl is a net.Dialer Control function that checks if the socket's
// destination IP address is blocked before establishing the connection.
func SafeControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid destination address %q: %w", address, err)
	}

	addr, ok := parseHostAddr(host)
	if !ok {
		return fmt.Errorf("invalid destination IP %q", host)
	}

	if IsBlockedAddr(addr) {
		return fmt.Errorf("%w: %s", ErrBlockedIP, addr.Unmap())
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

	if parsedAddr, ok := parseHostAddr(host); ok {
		if IsBlockedAddr(parsedAddr) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedIP, parsedAddr.Unmap())
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
// 4. Strips Authorization header on cross-origin redirects
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
		return errors.New("redirect URL has empty host")
	}

	if len(via) > 0 && via[0].URL != nil && !strings.EqualFold(host, via[0].URL.Hostname()) {
		req.Header.Del("Authorization")
	}

	if parsedAddr, ok := parseHostAddr(host); ok {
		if IsBlockedAddr(parsedAddr) {
			return fmt.Errorf("%w: %s", ErrBlockedIP, parsedAddr.Unmap())
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

// NewClient returns an *http.Client configured with SSRF protection,
// safe dialer/transport, and secure redirect handling.
func NewClient(timeout time.Duration) *http.Client {
	return NewSafeHTTPClient(timeout)
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
