package checker

import "time"

// Result represents the validation result for a single URL.
type Result struct {
	URL            string   `json:"url"`
	FinalURL       string   `json:"final_url"`
	RedirectCount  int      `json:"redirect_count"`
	RedirectURLs   []string `json:"redirect_urls"`
	StatusCode     int      `json:"status_code"`
	Status         string   `json:"status"`
	ResponseTimeMS int64    `json:"response_time_ms"`
	Error          string   `json:"error"`
}

// Config holds runtime configuration options for the URL checker.
type Config struct {
	InputPath  string
	OutputPath string
	Workers    int
	Timeout    time.Duration
	Retries    int
	UserAgent  string
}

// SummaryStats tracks overall metrics for a URL checking execution run.
type SummaryStats struct {
	Total          int `json:"total_urls"`
	StatusOK       int `json:"ok_200"`
	Status3xx      int `json:"redirects_3xx"`
	Status4xx      int `json:"client_errors_4xx"`
	Status5xx      int `json:"server_errors_5xx"`
	RequestErrors  int `json:"request_errors"`
	RedirectedURLs int `json:"redirected_urls"`
}
