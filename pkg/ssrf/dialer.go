package ssrf

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SafeDialer implements DNS pre-resolution, host resolution overrides, and IP validation.
type SafeDialer struct {
	Timeout             time.Duration
	Resolver            *net.Resolver
	AllowList           []string          // Optional host allowlist overrides
	HostResolutions     map[string]string // Target IP overrides: hostname -> override_ip
	AllowPrivateTargets bool              // Authorized staging/private network testing mode
}

// NewSafeDialer initializes a SafeDialer instance.
func NewSafeDialer(timeout time.Duration) *SafeDialer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &SafeDialer{
		Timeout:         timeout,
		Resolver:        net.DefaultResolver,
		HostResolutions: make(map[string]string),
	}
}

// ValidateDestination resolves the hostname and verifies all resolved IP addresses are safe.
// Returns the first valid public net.IP, host info, and whether an override was applied.
func (sd *SafeDialer) ValidateDestination(ctx context.Context, host string) (net.IP, string, bool, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	// 1. Check Target IP Override / Host Mapping first
	if len(sd.HostResolutions) > 0 {
		hostLower := strings.ToLower(strings.TrimSpace(hostname))
		if overrideIPStr, ok := sd.HostResolutions[hostLower]; ok && overrideIPStr != "" {
			ip := net.ParseIP(overrideIPStr)
			if ip == nil {
				return nil, "", true, fmt.Errorf("%w: invalid override IP address '%s' for host '%s'", ErrInvalidHost, overrideIPStr, hostname)
			}

			if IsIPRestricted(ip) && !sd.AllowPrivateTargets {
				return nil, "", true, fmt.Errorf("%w: override destination %s resolves to restricted/private IP", ErrPrivateIP, overrideIPStr)
			}

			return ip, hostname, true, nil
		}
	}

	if IsHostnameRestricted(hostname) {
		return nil, "", false, fmt.Errorf("%w: hostname '%s' is restricted", ErrPrivateIP, hostname)
	}

	// Direct IP check
	if ip := net.ParseIP(hostname); ip != nil {
		if IsIPRestricted(ip) && !sd.AllowPrivateTargets {
			return nil, "", false, fmt.Errorf("%w: %s", ErrPrivateIP, ip.String())
		}
		return ip, hostname, false, nil
	}

	// Normal DNS Resolution
	ips, err := sd.Resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, "", false, fmt.Errorf("%w: failed to resolve %s: %v", ErrInvalidHost, hostname, err)
	}

	if len(ips) == 0 {
		return nil, "", false, fmt.Errorf("%w: no IP addresses found for %s", ErrInvalidHost, hostname)
	}

	var validIP net.IP
	for _, ipAddr := range ips {
		ip := ipAddr.IP
		if IsIPRestricted(ip) && !sd.AllowPrivateTargets {
			return nil, "", false, fmt.Errorf("%w: %s resolves to restricted IP %s", ErrPrivateIP, hostname, ip.String())
		}
		if validIP == nil {
			validIP = ip
		}
	}

	return validIP, hostname, false, nil
}

// DialContext creates a net.Conn by pre-resolving host, checking for SSRF/override, and dialing the safe IP address.
func (sd *SafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address '%s': %w", addr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port '%s': %w", portStr, err)
	}

	ip, _, _, err := sd.ValidateDestination(ctx, host)
	if err != nil {
		return nil, err
	}

	targetAddr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout:   sd.Timeout,
		KeepAlive: 30 * time.Second,
	}

	return dialer.DialContext(ctx, network, targetAddr)
}

// NewHTTPClient returns an http.Client configured with SafeDialer transport and redirect validation.
func NewHTTPClient(timeout time.Duration, maxRedirects int, allowInsecureTLS bool) *http.Client {
	return NewHTTPClientWithResolutions(timeout, maxRedirects, allowInsecureTLS, nil, false)
}

// NewHTTPClientWithResolutions initializes HTTP client supporting Target IP Overrides and private testing policy.
func NewHTTPClientWithResolutions(timeout time.Duration, maxRedirects int, allowInsecureTLS bool, resolutions map[string]string, allowPrivate bool) *http.Client {
	safeDialer := NewSafeDialer(timeout)
	if resolutions != nil {
		safeDialer.HostResolutions = resolutions
	}
	safeDialer.AllowPrivateTargets = allowPrivate

	transport := &http.Transport{
		DialContext:         safeDialer.DialContext,
		TLSHandshakeTimeout: timeout,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: allowInsecureTLS,
		},
	}

	if maxRedirects < 0 {
		maxRedirects = 10
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}

			// Validate redirect destination URL for SSRF
			redirectURL := req.URL
			if redirectURL == nil {
				return fmt.Errorf("invalid redirect URL")
			}

			if IsHostnameRestricted(redirectURL.Hostname()) && !allowPrivate {
				return fmt.Errorf("%w: redirect destination '%s' is restricted", ErrPrivateIP, redirectURL.Hostname())
			}

			ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
			defer cancel()
			_, _, _, err := safeDialer.ValidateDestination(ctx, redirectURL.Hostname())
			if err != nil {
				return fmt.Errorf("SSRF blocked redirect to %s: %w", redirectURL.Host, err)
			}

			return nil
		},
	}

	return client
}

// SanitizeURL validates a raw URL string and checks for protocol and SSRF constraints.
func SanitizeURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported protocol '%s': only http and https are allowed", u.Scheme)
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("missing hostname in URL")
	}

	if IsHostnameRestricted(u.Hostname()) {
		return nil, fmt.Errorf("%w: hostname '%s' is restricted", ErrPrivateIP, u.Hostname())
	}

	return u, nil
}
