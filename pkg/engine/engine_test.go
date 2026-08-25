package engine

import (
	"context"
	"testing"
	"time"

	"github.com/senthilnasa/webpulse/pkg/scope"
)

func TestEngineSSRFAndScopeBlocking(t *testing.T) {
	policy := scope.ScopePolicy{
		AllowedPatterns: []string{"*.example.com", "example.org"},
	}

	eng := NewEngine(&policy)
	ctx := context.Background()
	profile := DefaultProfile("quick")

	// Test 1: SSRF blocked target
	resSSRF := eng.ProbeSingleURL(ctx, "test-job-1", "http://127.0.0.1/admin", profile, "203.0.113.1")
	if resSSRF.Status != "blocked" {
		t.Errorf("Expected 127.0.0.1 status to be 'blocked', got %s", resSSRF.Status)
	}

	// Test 2: Scope blocked target
	resScope := eng.ProbeSingleURL(ctx, "test-job-2", "https://unauthorized.com", profile, "203.0.113.1")
	if resScope.Status != "blocked" {
		t.Errorf("Expected unauthorized.com status to be 'blocked', got %s", resScope.Status)
	}
}

func TestEngineWorkerPool(t *testing.T) {
	eng := NewEngine(nil) // No scope restriction
	ctx := context.Background()
	profile := DefaultProfile("quick")
	profile.Timeout = 1 * time.Second

	urls := []string{
		"http://127.0.0.1",
		"http://169.254.169.254",
		"http://localhost:9000",
	}

	var progressCounts []int
	onProgress := func(completed, total int, res *TargetResult) {
		progressCounts = append(progressCounts, completed)
	}

	results := eng.ExecuteJob(ctx, "job-worker-test", urls, profile, onProgress)

	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}

	for _, res := range results {
		if res.Status != "blocked" {
			t.Errorf("Expected private URL %s to be blocked, got %s", res.URL, res.Status)
		}
	}

	if len(progressCounts) != 3 {
		t.Errorf("Expected 3 progress callbacks, got %d", len(progressCounts))
	}
}
