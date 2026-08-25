package ssrf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var (
	ErrPrivateIP      = errors.New("destination resolves to a private/restricted IP address")
	ErrInvalidHost    = errors.New("invalid target hostname or IP address")
	ErrCloudMetadata = errors.New("destination is a cloud metadata endpoint")
)

// Disallowed IP Prefixes
var restrictedPrefixes []netip.Prefix

func init() {
	rawPrefixes := []string{
		"0.0.0.0/8",          // Current network (only valid as source)
		"10.0.0.0/8",         // RFC 1918 Private IPv4
		"100.64.0.0/10",      // RFC 6598 Shared Address Space (CGNAT)
		"127.0.0.0/8",        // IPv4 Loopback
		"169.254.0.0/16",     // IPv4 Link-Local / Cloud Metadata
		"172.16.0.0/12",      // RFC 1918 Private IPv4
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // TEST-NET-1 (Documentation)
		"192.88.99.0/24",     // 6to4 Relay Anycast
		"192.168.0.0/16",     // RFC 1918 Private IPv4
		"198.18.0.0/15",      // Benchmarking
		"198.51.100.0/24",    // TEST-NET-2 (Documentation)
		"203.0.113.0/24",     // TEST-NET-3 (Documentation)
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved
		"255.255.255.255/32", // Limited Broadcast

		// IPv6 Ranges
		"::1/128",       // IPv6 Loopback
		"::/128",        // Unspecified Address
		"fc00::/7",      // IPv6 Unique Local (ULA)
		"fe80::/10",     // IPv6 Link-Local
		"2001:db8::/32", // IPv6 Documentation
		"ff00::/8",      // IPv6 Multicast
	}

	for _, str := range rawPrefixes {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			panic(fmt.Sprintf("invalid prefix in init: %s: %v", str, err))
		}
		restrictedPrefixes = append(restrictedPrefixes, prefix)
	}
}

// IsIPRestricted returns true if an IP address falls inside private/restricted ranges.
func IsIPRestricted(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Convert net.IP to netip.Addr and unmap IPv4-in-IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()

	if !addr.IsValid() {
		return true
	}

	// Check loopback & unspecified
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() {
		return true
	}

	// Check explicit restricted prefixes
	for _, prefix := range restrictedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

// IsHostnameRestricted performs basic string checks for common loopback and cloud metadata names.
func IsHostnameRestricted(host string) bool {
	hostLower := strings.ToLower(strings.TrimSpace(host))

	// Strip port if present
	if h, _, err := net.SplitHostPort(hostLower); err == nil {
		hostLower = h
	}

	if hostLower == "localhost" ||
		strings.HasSuffix(hostLower, ".localhost") ||
		strings.HasSuffix(hostLower, ".local") ||
		strings.HasSuffix(hostLower, ".internal") ||
		hostLower == "metadata.google.internal" ||
		hostLower == "instance-data" {
		return true
	}

	// Try parsing as IP directly
	if ip := net.ParseIP(hostLower); ip != nil {
		return IsIPRestricted(ip)
	}

	return false
}
