package scope

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

var ErrScopeViolation = errors.New("target URL is outside the authorized target scope")

// ScopePolicy defines allowed and blocked hostname rules.
type ScopePolicy struct {
	AllowedPatterns []string `json:"allowed_patterns"`
	BlockedPatterns []string `json:"blocked_patterns"`
}

// ScopeValidator checks hostnames and URLs against policy rules.
type ScopeValidator struct {
	Policy ScopePolicy
}

// NewScopeValidator initializes a validator with the given policy.
func NewScopeValidator(policy ScopePolicy) *ScopeValidator {
	return &ScopeValidator{Policy: policy}
}

// MatchPattern checks if a hostname matches a glob pattern (e.g. "*.example.com" or "example.com").
func MatchPattern(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))

	if pattern == "*" || pattern == "" {
		return true
	}

	if pattern == host {
		return true
	}

	// Support wildcard prefix like *.example.com matching sub.example.com
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	// Fallback to filepath.Match
	matched, err := filepath.Match(pattern, host)
	if err == nil && matched {
		return true
	}

	return false
}

// ValidateHost checks if a hostname is permitted under the policy rules.
func (sv *ScopeValidator) ValidateHost(host string) error {
	host = strings.ToLower(strings.TrimSpace(host))

	// Check blocked patterns first
	for _, pattern := range sv.Policy.BlockedPatterns {
		if MatchPattern(pattern, host) {
			return fmt.Errorf("%w: host '%s' matches explicit blocked pattern '%s'", ErrScopeViolation, host, pattern)
		}
	}

	// If no allowed patterns defined, default to allowing all non-blocked hosts
	if len(sv.Policy.AllowedPatterns) == 0 {
		return nil
	}

	// Must match at least one allowed pattern if allowed rules exist
	for _, pattern := range sv.Policy.AllowedPatterns {
		if MatchPattern(pattern, host) {
			return nil
		}
	}

	return fmt.Errorf("%w: host '%s' is not in the allowed scopes list %v", ErrScopeViolation, host, sv.Policy.AllowedPatterns)
}

// ValidateURL checks if a full URL is permitted under the scope policy rules.
func (sv *ScopeValidator) ValidateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing hostname in URL")
	}

	return sv.ValidateHost(host)
}
