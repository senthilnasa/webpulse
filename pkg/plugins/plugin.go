package plugins

import (
	"context"
	"time"
)

// TargetSpec holds parameters for probing a target URL.
type TargetSpec struct {
	URL                 string            `json:"url"`
	Method              string            `json:"method"`
	Headers             map[string]string `json:"headers"`
	UserAgent           string            `json:"user_agent"`
	Timeout             time.Duration     `json:"timeout"`
	AllowInsecureTLS    bool              `json:"allow_insecure_tls"`
	MaxRedirects        int               `json:"max_redirects"`
	HostResolutions     map[string]string `json:"host_resolutions,omitempty"`     // Target IP Overrides (hostname -> override_ip)
	AllowPrivateTargets bool              `json:"allow_private_targets,omitempty"` // Authorized private network testing policy
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
	Version             string `json:"version"`
	CipherSuite         string `json:"cipher_suite"`
	Issuer              string `json:"issuer"`
	Subject             string `json:"subject"`
	Expiry              string `json:"expiry"`
	SNI                 string `json:"tls_sni,omitempty"`
	ValidationStatus    string `json:"validation_status"` // "Valid", "Invalid"
	ValidationDetails   string `json:"validation_details,omitempty"`
}

// RoutingResult captures Target IP Override details and network routing path.
type RoutingResult struct {
	Hostname           string `json:"hostname"`
	DNSIP              string `json:"dns_ip,omitempty"`
	OverrideIP         string `json:"override_ip,omitempty"`
	ActualConnectionIP string `json:"actual_connection_ip"`
	HostHeader         string `json:"host_header"`
	TLSSNI             string `json:"tls_sni,omitempty"`
	IsOverrideActive   bool   `json:"is_override_active"`
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
	Routing           RoutingResult     `json:"routing"`
	ErrorMessage      string            `json:"error_message,omitempty"`
}

// DiagnosticPlugin is the standard interface for diagnostic modules.
type DiagnosticPlugin interface {
	Name() string
	Description() string
	Execute(ctx context.Context, target *TargetSpec) (*PluginResult, error)
}
