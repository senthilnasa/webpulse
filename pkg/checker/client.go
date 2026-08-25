package checker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type redirectKey struct{}

type redirectTracker struct {
	mu   sync.Mutex
	urls []string
}

// HTTPChecker handles making HTTP requests with connection pooling, retries, and redirect tracking.
type HTTPChecker struct {
	config Config
	client *http.Client
}

// NewHTTPChecker initializes a new HTTPChecker instance with optimized connection pooling.
func NewHTTPChecker(cfg Config) *HTTPChecker {
	workers := cfg.Workers
	if workers <= 0 {
		workers = 10
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          workers * 2,
		MaxIdleConnsPerHost:   workers,
		MaxConnsPerHost:       workers,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if tracker, ok := req.Context().Value(redirectKey{}).(*redirectTracker); ok {
				tracker.mu.Lock()
				tracker.urls = append(tracker.urls, req.URL.String())
				tracker.mu.Unlock()
			}
			if cfg.UserAgent != "" {
				req.Header.Set("User-Agent", cfg.UserAgent)
			}
			return nil
		},
	}

	return &HTTPChecker{
		config: cfg,
		client: client,
	}
}

// CheckURL validates a target URL with automatic retries for temporary failures.
func (c *HTTPChecker) CheckURL(ctx context.Context, targetURL string) Result {
	start := time.Now()
	var finalResult Result
	finalResult.URL = targetURL
	finalResult.RedirectURLs = make([]string, 0)

	maxAttempts := 1 + c.config.Retries
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			finalResult.Error = "operation cancelled"
			finalResult.Status = "ERROR"
			finalResult.StatusCode = 0
			finalResult.ResponseTimeMS = time.Since(start).Milliseconds()
			return finalResult
		}

		res, isRetriable := c.doSingleRequest(ctx, targetURL)
		res.ResponseTimeMS = time.Since(start).Milliseconds()
		finalResult = res

		if !isRetriable || attempt == maxAttempts {
			break
		}

		// Backoff delay before retry
		select {
		case <-ctx.Done():
			finalResult.Error = "operation cancelled"
			finalResult.Status = "ERROR"
			finalResult.StatusCode = 0
			finalResult.ResponseTimeMS = time.Since(start).Milliseconds()
			return finalResult
		case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
		}
	}

	return finalResult
}

func (c *HTTPChecker) doSingleRequest(ctx context.Context, targetURL string) (Result, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	tracker := &redirectTracker{urls: make([]string, 0)}
	reqCtx = context.WithValue(reqCtx, redirectKey{}, tracker)

	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return Result{
			URL:            targetURL,
			FinalURL:       "",
			RedirectCount:  0,
			RedirectURLs:   make([]string, 0),
			StatusCode:     0,
			Status:         "ERROR",
			Error:          "invalid URL format",
		}, false
	}

	req, err := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil)
	if err != nil {
		return Result{
			URL:            targetURL,
			FinalURL:       "",
			RedirectCount:  0,
			RedirectURLs:   make([]string, 0),
			StatusCode:     0,
			Status:         "ERROR",
			Error:          CleanErrorMessage(err),
		}, false
	}

	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.client.Do(req)

	tracker.mu.Lock()
	redirectHops := make([]string, len(tracker.urls))
	copy(redirectHops, tracker.urls)
	tracker.mu.Unlock()

	if err != nil {
		return Result{
			URL:            targetURL,
			FinalURL:       "",
			RedirectCount:  len(redirectHops),
			RedirectURLs:   redirectHops,
			StatusCode:     0,
			Status:         "ERROR",
			Error:          CleanErrorMessage(err),
		}, true // Network/timeout error is retriable
	}
	defer resp.Body.Close()

	// Consume up to 4KB of body and close to enable HTTP keep-alive connection reuse
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)

	finalURL := targetURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	statusStr := CategorizeStatus(resp.StatusCode, nil)
	res := Result{
		URL:            targetURL,
		FinalURL:       finalURL,
		RedirectCount:  len(redirectHops),
		RedirectURLs:   redirectHops,
		StatusCode:     resp.StatusCode,
		Status:         statusStr,
		Error:          "",
	}

	// Retry on 5xx Server Errors
	isRetriable := resp.StatusCode >= 500 && resp.StatusCode < 600
	return res, isRetriable
}

// CategorizeStatus returns the classification string for an HTTP status code.
func CategorizeStatus(statusCode int, err error) string {
	if err != nil || statusCode == 0 {
		return "ERROR"
	}
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "OK"
	case statusCode >= 300 && statusCode < 400:
		return "3xx Redirect"
	case statusCode >= 400 && statusCode < 500:
		return "4xx Client Error"
	case statusCode >= 500 && statusCode < 600:
		return "5xx Server Error"
	default:
		return "ERROR"
	}
}

// CleanErrorMessage normalizes raw Go network error strings into concise, user-friendly messages.
func CleanErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errStr, "Client.Timeout") || strings.Contains(errStr, "deadline exceeded") || strings.Contains(errStr, "timeout") {
		return "timeout"
	}
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup") {
		return "DNS lookup failed"
	}
	if strings.Contains(errStr, "connection refused") {
		return "connection refused"
	}
	if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "tls") || strings.Contains(errStr, "x509") {
		return "TLS/SSL error"
	}
	if strings.Contains(errStr, "stopped after 10 redirects") {
		return "too many redirects"
	}

	// Trim request method prefix if present
	if idx := strings.Index(errStr, ": "); idx != -1 && (strings.HasPrefix(errStr, "Get ") || strings.HasPrefix(errStr, "Head ")) {
		return errStr[idx+2:]
	}
	return errStr
}
