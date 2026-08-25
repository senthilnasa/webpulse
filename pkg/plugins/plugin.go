package plugins

import (
	"context"
	"time"
)

// TargetSpec holds parameters for probing a target URL.
type TargetSpec struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	Headers          map[string]string `json:"headers"`
	UserAgent        string            `json:"user_agent"`
	Timeout          time.Duration     `json:"timeout"`
	AllowInsecureTLS bool              `json:"allow_insecure_tls"`
	MaxRedirects     int               `json:"max_redirects"`
}

// DiagnosticsResult captures network phase latencies.
type DiagnosticsResult struct {
	DNSLookupMS    int64 `json:"dns_ms"`
	TCPConnectMS   int64 `json:"tcp_ms"`
	TLSHandshakeMS int64 `json:"tls_ms"`
	HTTPTTFBMS     int64 `json:"ttfb_ms"`
}

// TLSInfo captures SSL/TLS security certificate details.
type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	Expiry      string `json:"expiry"`
}

// PluginResult contains diagnostic metrics produced by a plugin.
type PluginResult struct {
	PluginName        string            `json:"plugin_name"`
	Success           bool              `json:"success"`
	HTTPStatus        int               `json:"http_status"`
	StatusText        string            `json:"status_text"`
	ResolvedIP        string            `json:"resolved_ip"`
	IsPrivateIP       bool              `json:"is_private_ip"`
	ResponseTimeMS    int64             `json:"response_time_ms"`
	ResponseSizeBytes int64             `json:"response_size_bytes"`
	ContentType       string            `json:"content_type"`
	Headers           map[string]string `json:"headers,omitempty"`
	Redirects         []string          `json:"redirects,omitempty"`
	Diagnostics       DiagnosticsResult `json:"diagnostics"`
	TLS               *TLSInfo          `json:"tls,omitempty"`
	ErrorMessage      string            `json:"error_message,omitempty"`
}

// DiagnosticPlugin is the standard interface for diagnostic modules.
type DiagnosticPlugin interface {
	Name() string
	Description() string
	Execute(ctx context.Context, target *TargetSpec) (*PluginResult, error)
}
