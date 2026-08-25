package engine

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/senthilnasa/webpulse/pkg/egress"
	"github.com/senthilnasa/webpulse/pkg/plugins"
	"github.com/senthilnasa/webpulse/pkg/scope"
	"github.com/senthilnasa/webpulse/pkg/ssrf"
)

// ProfileConfig represents a pre-configured execution profile (Quick, Standard, Comprehensive).
type ProfileConfig struct {
	Name            string            `json:"name"`
	Timeout         time.Duration     `json:"timeout"`
	Workers         int               `json:"workers"`
	Retries         int               `json:"retries"`
	MaxRedirects    int               `json:"max_redirects"`
	UserAgent       string            `json:"user_agent"`
	Headers         map[string]string `json:"headers"`
	AllowInsecure   bool              `json:"allow_insecure"`
	RPSLimit        int               `json:"rps_limit"`
}

func DefaultProfile(name string) ProfileConfig {
	switch name {
	case "quick":
		return ProfileConfig{
			Name:         "quick",
			Timeout:      5 * time.Second,
			Workers:      20,
			Retries:      1,
			MaxRedirects: 3,
			UserAgent:    "WebPulse-Engine/1.0 (Quick)",
		}
	case "comprehensive":
		return ProfileConfig{
			Name:         "comprehensive",
			Timeout:      15 * time.Second,
			Workers:      5,
			Retries:      3,
			MaxRedirects: 10,
			UserAgent:    "WebPulse-Engine/1.0 (Comprehensive)",
		}
	default: // "standard"
		return ProfileConfig{
			Name:         "standard",
			Timeout:      10 * time.Second,
			Workers:      10,
			Retries:      2,
			MaxRedirects: 5,
			UserAgent:    "WebPulse-Engine/1.0",
		}
	}
}

// TargetResult holds full diagnostic results for a single URL target conforming to canonical schema.
type TargetResult struct {
	SchemaVersion int                    `json:"schema_version"`
	JobID         string                 `json:"job_id,omitempty"`
	URL           string                 `json:"url"`
	Timestamp     time.Time              `json:"timestamp"`
	Status        string                 `json:"status"` // "completed", "failed", "blocked", "skipped"
	Target        TargetMeta             `json:"target"`
	Request       RequestMeta            `json:"request"`
	Response      ResponseMeta           `json:"response"`
	Diagnostics   plugins.DiagnosticsResult `json:"diagnostics"`
	TLS           *plugins.TLSInfo       `json:"tls,omitempty"`
	Security      SecurityMeta           `json:"security"`
	Errors        []string               `json:"errors,omitempty"`
}

type TargetMeta struct {
	URL        string `json:"url"`
	Hostname   string `json:"hostname"`
	ResolvedIP string `json:"resolved_ip"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
}

type RequestMeta struct {
	Method      string    `json:"method"`
	UserAgent   string    `json:"user_agent"`
	EgressIP    string    `json:"egress_ip"`
	RequestTime time.Time `json:"request_time"`
}

type ResponseMeta struct {
	HTTPStatus    int      `json:"http_status"`
	StatusText    string   `json:"status_text"`
	TotalTimeMS   int64    `json:"total_time_ms"`
	SizeBytes     int64    `json:"size_bytes"`
	ContentType   string   `json:"content_type"`
	Redirects     []string `json:"redirects,omitempty"`
}

type SecurityMeta struct {
	IsPrivateIP     bool `json:"is_private_ip"`
	SSRFValidated   bool `json:"ssrf_validated"`
	ScopeAuthorized bool `json:"scope_authorized"`
}

// DiagnosticEngine manages job worker pools and probes URLs.
type DiagnosticEngine struct {
	ScopeValidator *scope.ScopeValidator
	HTTPPlugin     *plugins.HTTPProbePlugin
}

func NewEngine(scopePolicy *scope.ScopePolicy) *DiagnosticEngine {
	var validator *scope.ScopeValidator
	if scopePolicy != nil {
		validator = scope.NewScopeValidator(*scopePolicy)
	}
	return &DiagnosticEngine{
		ScopeValidator: validator,
		HTTPPlugin:     plugins.NewHTTPProbePlugin(),
	}
}

// ProgressCallback is used to stream real-time updates.
type ProgressCallback func(completedCount, totalCount int, currentResult *TargetResult)

// ExecuteJob runs URL probes across a worker pool with progress updates.
func (e *DiagnosticEngine) ExecuteJob(ctx context.Context, jobID string, urls []string, profile ProfileConfig, onProgress ProgressCallback) []*TargetResult {
	if profile.Workers <= 0 {
		profile.Workers = 10
	}

	egressInfo, _ := egress.DetectEgressInfo(ctx, false)
	egressIP := ""
	if egressInfo != nil {
		egressIP = egressInfo.IPv4
	}

	total := len(urls)
	results := make([]*TargetResult, total)
	urlChan := make(chan struct {
		index int
		rawURL string
	}, total)

	for i, u := range urls {
		urlChan <- struct {
			index  int
			rawURL string
		}{index: i, rawURL: u}
	}
	close(urlChan)

	var completedCounter int32
	var wg sync.WaitGroup

	workers := profile.Workers
	if workers > total {
		workers = total
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range urlChan {
				select {
				case <-ctx.Done():
					// Job cancelled
					res := &TargetResult{
						SchemaVersion: 1,
						JobID:         jobID,
						URL:           item.rawURL,
						Timestamp:     time.Now(),
						Status:        "skipped",
						Errors:        []string{"Job cancelled"},
					}
					results[item.index] = res
					continue
				default:
				}

				res := e.ProbeSingleURL(ctx, jobID, item.rawURL, profile, egressIP)
				results[item.index] = res

				c := atomic.AddInt32(&completedCounter, 1)
				if onProgress != nil {
					onProgress(int(c), total, res)
				}
			}
		}()
	}

	wg.Wait()
	return results
}

// ProbeSingleURL validates scope/SSRF and executes diagnostic probes for a single target URL.
func (e *DiagnosticEngine) ProbeSingleURL(ctx context.Context, jobID string, rawURL string, profile ProfileConfig, egressIP string) *TargetResult {
	now := time.Now()
	res := &TargetResult{
		SchemaVersion: 1,
		JobID:         jobID,
		URL:           rawURL,
		Timestamp:     now,
		Status:        "completed",
		Request: RequestMeta{
			Method:      "GET",
			UserAgent:   profile.UserAgent,
			EgressIP:    egressIP,
			RequestTime: now,
		},
		Security: SecurityMeta{
			SSRFValidated:   true,
			ScopeAuthorized: true,
		},
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		res.Status = "failed"
		res.Errors = append(res.Errors, fmt.Sprintf("Invalid URL syntax: %v", err))
		return res
	}

	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		fmt.Sscanf(u.Port(), "%d", &port)
	}

	res.Target = TargetMeta{
		URL:      rawURL,
		Hostname: u.Hostname(),
		Port:     port,
		Protocol: u.Scheme,
	}

	// 1. Scope Validation Check
	if e.ScopeValidator != nil {
		if err := e.ScopeValidator.ValidateURL(rawURL); err != nil {
			res.Status = "blocked"
			res.Security.ScopeAuthorized = false
			res.Errors = append(res.Errors, fmt.Sprintf("Target Scope Violation: %v", err))
			return res
		}
	}

	// 2. Hostname SSRF Check
	if ssrf.IsHostnameRestricted(u.Hostname()) {
		res.Status = "blocked"
		res.Security.SSRFValidated = false
		res.Security.IsPrivateIP = true
		res.Errors = append(res.Errors, "SSRF Defense Blocked: Target resolves to private or loopback IP range")
		return res
	}

	// 3. Diagnostic Probe Execution
	targetSpec := &plugins.TargetSpec{
		URL:              rawURL,
		Method:           "GET",
		UserAgent:        profile.UserAgent,
		Timeout:          profile.Timeout,
		AllowInsecureTLS: profile.AllowInsecure,
		MaxRedirects:     profile.MaxRedirects,
		Headers:          profile.Headers,
	}

	var pRes *plugins.PluginResult
	for attempt := 0; attempt <= profile.Retries; attempt++ {
		pRes, err = e.HTTPPlugin.Execute(ctx, targetSpec)
		if err == nil && pRes.Success {
			break
		}
		if attempt < profile.Retries {
			time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond) // Exponential backoff
		}
	}

	if pRes != nil {
		res.Target.ResolvedIP = pRes.ResolvedIP
		res.Response = ResponseMeta{
			HTTPStatus:  pRes.HTTPStatus,
			StatusText:  pRes.StatusText,
			TotalTimeMS: pRes.ResponseTimeMS,
			SizeBytes:   pRes.ResponseSizeBytes,
			ContentType: pRes.ContentType,
			Redirects:   pRes.Redirects,
		}
		res.Diagnostics = pRes.Diagnostics
		res.TLS = pRes.TLS

		if !pRes.Success {
			res.Status = "failed"
			if pRes.ErrorMessage != "" {
				res.Errors = append(res.Errors, pRes.ErrorMessage)
			}
		}
	} else if err != nil {
		res.Status = "failed"
		res.Errors = append(res.Errors, err.Error())
	}

	return res
}
