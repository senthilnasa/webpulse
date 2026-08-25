package scope

import (
	"testing"
)

func TestScopeValidator(t *testing.T) {
	policy := ScopePolicy{
		AllowedPatterns: []string{"*.example.com", "example.org", "api.service.net"},
		BlockedPatterns: []string{"internal.example.com", "secret.*"},
	}

	validator := NewScopeValidator(policy)

	allowedURLs := []string{
		"https://example.com",
		"https://sub.example.com",
		"https://api.example.com/health",
		"http://example.org",
		"https://api.service.net/v1",
	}

	for _, rawURL := range allowedURLs {
		err := validator.ValidateURL(rawURL)
		if err != nil {
			t.Errorf("Expected URL '%s' to be allowed by scope policy, but got error: %v", rawURL, err)
		}
	}

	blockedURLs := []string{
		"https://internal.example.com/admin",
		"https://secret.example.com",
		"https://unauthorized.org",
		"https://google.com",
	}

	for _, rawURL := range blockedURLs {
		err := validator.ValidateURL(rawURL)
		if err == nil {
			t.Errorf("Expected URL '%s' to be rejected by scope policy, but it succeeded", rawURL)
		}
	}
}
