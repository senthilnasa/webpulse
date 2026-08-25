package checker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ResultCollector manages thread-safe result collection, logging, and metrics tracking.
type ResultCollector struct {
	mu           sync.Mutex
	total        int
	processed    int
	results      []Result
	summaryStats SummaryStats
}

// NewResultCollector initializes a collector for total URLs.
func NewResultCollector(total int) *ResultCollector {
	return &ResultCollector{
		total:   total,
		results: make([]Result, 0, total),
	}
}

// Add records a result thread-safely and logs the progress line to stdout.
func (c *ResultCollector) Add(res Result) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results = append(c.results, res)
	c.processed++

	c.updateStats(res)

	// Format progress line: [1250/10000] 200 https://example.com/page
	statusDisplay := "ERROR"
	if res.StatusCode > 0 {
		statusDisplay = fmt.Sprintf("%d", res.StatusCode)
	}

	fmt.Printf("[%d/%d] %s %s\n", c.processed, c.total, statusDisplay, res.URL)
	_ = os.Stdout.Sync()
}

func (c *ResultCollector) updateStats(res Result) {
	c.summaryStats.Total++
	if res.RedirectCount > 0 {
		c.summaryStats.RedirectedURLs++
	}
	switch res.Status {
	case "OK":
		c.summaryStats.StatusOK++
	case "3xx Redirect":
		c.summaryStats.Status3xx++
	case "4xx Client Error":
		c.summaryStats.Status4xx++
	case "5xx Server Error":
		c.summaryStats.Status5xx++
	case "ERROR":
		c.summaryStats.RequestErrors++
	default:
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			c.summaryStats.StatusOK++
		} else if res.StatusCode >= 300 && res.StatusCode < 400 {
			c.summaryStats.Status3xx++
		} else if res.StatusCode >= 400 && res.StatusCode < 500 {
			c.summaryStats.Status4xx++
		} else if res.StatusCode >= 500 && res.StatusCode < 600 {
			c.summaryStats.Status5xx++
		} else {
			c.summaryStats.RequestErrors++
		}
	}
}

// Results returns a snapshot copy of all collected results.
func (c *ResultCollector) Results() []Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]Result, len(c.results))
	copy(copied, c.results)
	return copied
}

// Summary returns current aggregated statistics.
func (c *ResultCollector) Summary() SummaryStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.summaryStats
}

// WriteJSONResults formats and writes results to a JSON file.
func WriteJSONResults(path string, results []Result) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode JSON results: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write output file %s: %w", path, err)
	}

	return nil
}

// PrintSummary outputs formatted metrics to stdout.
func PrintSummary(stats SummaryStats) {
	fmt.Println()
	fmt.Printf("Total URLs:      %d\n", stats.Total)
	fmt.Printf("200 OK:          %d\n", stats.StatusOK)
	fmt.Printf("3xx Redirects:   %d\n", stats.Status3xx)
	fmt.Printf("4xx Errors:      %d\n", stats.Status4xx)
	fmt.Printf("5xx Errors:      %d\n", stats.Status5xx)
	fmt.Printf("Request Errors:  %d\n", stats.RequestErrors)
	fmt.Printf("Redirected URLs: %d\n", stats.RedirectedURLs)
}
