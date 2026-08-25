package ssrf

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestIsIPRestricted(t *testing.T) {
	blockedIPs := []string{
		"127.0.0.1",
		"127.0.0.5",
		"10.0.0.1",
		"10.255.255.254",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.0.1",
		"192.168.100.50",
		"169.254.169.254", // Cloud Metadata
		"100.64.0.1",     // CGNAT
		"0.0.0.0",
		"::1",
		"fc00::1",
		"fe80::1",
		"::ffff:127.0.0.1", // IPv4-mapped IPv6 loopback
		"::ffff:10.0.0.1",  // IPv4-mapped IPv6 private
	}

	for _, ipStr := range blockedIPs {
		ip := net.ParseIP(ipStr)
		if !IsIPRestricted(ip) {
			t.Errorf("Expected IP %s to be restricted/blocked, but it was allowed", ipStr)
		}
	}

	allowedIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
		"142.250.190.46",
	}

	for _, ipStr := range allowedIPs {
		ip := net.ParseIP(ipStr)
		if IsIPRestricted(ip) {
			t.Errorf("Expected public IP %s to be allowed, but it was restricted", ipStr)
		}
	}
}

func TestIsHostnameRestricted(t *testing.T) {
	blockedHosts := []string{
		"localhost",
		"LOCALHOST",
		"app.localhost",
		"service.local",
		"metadata.google.internal",
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
	}

	for _, host := range blockedHosts {
		if !IsHostnameRestricted(host) {
			t.Errorf("Expected hostname %s to be restricted, but it passed", host)
		}
	}

	allowedHosts := []string{
		"example.com",
		"api.github.com",
		"google.com",
	}

	for _, host := range allowedHosts {
		if IsHostnameRestricted(host) {
			t.Errorf("Expected hostname %s to be allowed, but it was restricted", host)
		}
	}
}

func TestSanitizeURL(t *testing.T) {
	invalidURLs := []string{
		"http://localhost/admin",
		"http://127.0.0.1:8080",
		"http://169.254.169.254/latest/meta-data/",
		"file:///etc/passwd",
		"ftp://example.com/file",
		"gopher://example.com",
		"http://10.0.0.1/",
	}

	for _, rawURL := range invalidURLs {
		_, err := SanitizeURL(rawURL)
		if err == nil {
			t.Errorf("Expected URL '%s' to be rejected by SanitizeURL, but it succeeded", rawURL)
		}
	}

	validURLs := []string{
		"https://example.com",
		"http://example.org/path?query=1",
		"https://api.github.com/status",
	}

	for _, rawURL := range validURLs {
		u, err := SanitizeURL(rawURL)
		if err != nil {
			t.Errorf("Expected URL '%s' to be valid, got error: %v", rawURL, err)
		}
		if u == nil {
			t.Errorf("Expected parsed URL object for '%s'", rawURL)
		}
	}
}

func TestSafeDialerValidation(t *testing.T) {
	dialer := NewSafeDialer(2 * time.Second)
	ctx := context.Background()

	_, _, _, err := dialer.ValidateDestination(ctx, "127.0.0.1")
	if err == nil {
		t.Error("Expected 127.0.0.1 validation to fail with SSRF error")
	}

	_, _, _, err = dialer.ValidateDestination(ctx, "169.254.169.254")
	if err == nil {
		t.Error("Expected metadata IP validation to fail with SSRF error")
	}
}

func TestTargetIPOverrideValidation(t *testing.T) {
	dialer := NewSafeDialer(2 * time.Second)
	dialer.HostResolutions["example.com"] = "93.184.216.34"
	ctx := context.Background()

	ip, host, isOverride, err := dialer.ValidateDestination(ctx, "example.com")
	if err != nil {
		t.Fatalf("Unexpected error for target IP override: %v", err)
	}
	if !isOverride {
		t.Error("Expected isOverride to be true")
	}
	if ip.String() != "93.184.216.34" {
		t.Errorf("Expected IP 93.184.216.34, got %s", ip.String())
	}
	if host != "example.com" {
		t.Errorf("Expected host example.com, got %s", host)
	}
}
