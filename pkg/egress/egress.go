package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EgressInfo holds the detected public IPv4 and IPv6 addresses and verification status.
type EgressInfo struct {
	IPv4          string    `json:"ipv4"`
	IPv6          string    `json:"ipv6"`
	DetectedBy    string    `json:"detected_by"`
	LastCheckedAt time.Time `json:"last_checked_at"`
	Status        string    `json:"status"`
	ErrorMessage  string    `json:"error_message,omitempty"`
}

var (
	cachedInfo *EgressInfo
	cacheMutex sync.RWMutex
	cacheTTL   = 5 * time.Minute
)

// IPv4 and IPv6 echo service endpoints
var ipv4Endpoints = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
}

var ipv6Endpoints = []string{
	"https://api64.ipify.org",
}

// FetchPublicIPWithClient queries an HTTP endpoint with a custom HTTP client to obtain the caller's public IP address.
func FetchPublicIPWithClient(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "WebPulse-Engine/1.0")

	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", err
	}

	ipStr := strings.TrimSpace(string(body))
	if parsedIP := net.ParseIP(ipStr); parsedIP != nil {
		return parsedIP.String(), nil
	}

	return "", fmt.Errorf("invalid IP format returned: %s", ipStr)
}

// FetchPublicIP queries an HTTP endpoint to obtain the caller's public IP address.
func FetchPublicIP(ctx context.Context, endpoint string) (string, error) {
	return FetchPublicIPWithClient(ctx, nil, endpoint)
}

// DetectEgressInfo checks for current public IPv4 and IPv6 addresses with caching.
func DetectEgressInfo(ctx context.Context, forceRefresh bool) (*EgressInfo, error) {
	cacheMutex.RLock()
	if !forceRefresh && cachedInfo != nil && time.Since(cachedInfo.LastCheckedAt) < cacheTTL {
		info := *cachedInfo
		cacheMutex.RUnlock()
		return &info, nil
	}
	cacheMutex.RUnlock()

	info := &EgressInfo{
		LastCheckedAt: time.Now(),
		Status:        "ok",
	}

	// Resolve IPv4
	client := &http.Client{Timeout: 4 * time.Second}
	for _, ep := range ipv4Endpoints {
		subCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ip, err := FetchPublicIPWithClient(subCtx, client, ep)
		cancel()
		if err == nil && ip != "" {
			info.IPv4 = ip
			info.DetectedBy = ep
			break
		}
	}

	if info.IPv4 == "" {
		info.Status = "degraded"
		info.ErrorMessage = "Unable to resolve public IPv4 address"
	}

	// Cache result
	cacheMutex.Lock()
	cachedInfo = info
	cacheMutex.Unlock()

	return info, nil
}
