package plugins

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/senthilnasa/webpulse/pkg/ssrf"
)

// HTTPProbePlugin measures HTTP/HTTPS diagnostic metrics with SSRF dialer protection and httptrace.
type HTTPProbePlugin struct{}

func NewHTTPProbePlugin() *HTTPProbePlugin {
	return &HTTPProbePlugin{}
}

func (p *HTTPProbePlugin) Name() string {
	return "http_probe"
}

func (p *HTTPProbePlugin) Description() string {
	return "Executes HTTP/HTTPS requests and measures DNS, TCP, TLS, and TTFB latencies safely."
}

func (p *HTTPProbePlugin) Execute(ctx context.Context, target *TargetSpec) (*PluginResult, error) {
	parsedURL, err := ssrf.SanitizeURL(target.URL)
	if err != nil {
		return &PluginResult{
			PluginName:   p.Name(),
			Success:      false,
			ErrorMessage: fmt.Sprintf("SSRF / URL Validation Blocked: %v", err),
		}, nil
	}

	method := target.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if target.UserAgent != "" {
		req.Header.Set("User-Agent", target.UserAgent)
	} else {
		req.Header.Set("User-Agent", "WebPulse-Engine/1.0")
	}

	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	var (
		dnsStart, dnsDone   time.Time
		tcpStart, tcpDone   time.Time
		tlsStart, tlsDone   time.Time
		reqStart, firstByte time.Time
		resolvedIP          string
		redirects           []string
		tlsState            *tls.ConnectionState
	)

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
			if len(info.Addrs) > 0 {
				resolvedIP = info.Addrs[0].String()
			}
		},
		ConnectStart: func(_, _ string) { tcpStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) { tcpDone = time.Now() },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			tlsDone = time.Now()
			tlsState = &state
		},
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := ssrf.NewHTTPClient(target.Timeout, target.MaxRedirects, target.AllowInsecureTLS)

	// Wrap redirect logic to collect redirect URLs
	origRedirect := client.CheckRedirect
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		redirects = append(redirects, r.URL.String())
		if origRedirect != nil {
			return origRedirect(r, via)
		}
		return nil
	}

	reqStart = time.Now()
	resp, err := client.Do(req)
	totalDuration := time.Since(reqStart)

	result := &PluginResult{
		PluginName:     p.Name(),
		ResponseTimeMS: totalDuration.Milliseconds(),
		Redirects:      redirects,
	}

	if err != nil {
		result.Success = false
		result.ErrorMessage = err.Error()
		return result, nil
	}
	defer resp.Body.Close()

	// Read body size (limited to 5MB max)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))

	result.Success = resp.StatusCode < 400
	result.HTTPStatus = resp.StatusCode
	result.StatusText = resp.Status
	result.ResponseSizeBytes = int64(len(bodyBytes))
	result.ContentType = resp.Header.Get("Content-Type")
	result.ResolvedIP = resolvedIP

	// Headers
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}
	result.Headers = respHeaders

	// Latencies
	var dnsMS, tcpMS, tlsMS, ttfbMS int64
	if !dnsDone.IsZero() && !dnsStart.IsZero() {
		dnsMS = dnsDone.Sub(dnsStart).Milliseconds()
	}
	if !tcpDone.IsZero() && !tcpStart.IsZero() {
		tcpMS = tcpDone.Sub(tcpStart).Milliseconds()
	}
	if !tlsDone.IsZero() && !tlsStart.IsZero() {
		tlsMS = tlsDone.Sub(tlsStart).Milliseconds()
	}
	if !firstByte.IsZero() && !reqStart.IsZero() {
		ttfbMS = firstByte.Sub(reqStart).Milliseconds()
	}

	result.Diagnostics = DiagnosticsResult{
		DNSLookupMS:    dnsMS,
		TCPConnectMS:   tcpMS,
		TLSHandshakeMS: tlsMS,
		HTTPTTFBMS:     ttfbMS,
	}

	// TLS Details
	if resp.TLS != nil {
		tlsState = resp.TLS
	}
	if tlsState != nil {
		tlsInfo := &TLSInfo{
			Version: tlsVersionName(tlsState.Version),
		}
		if len(tlsState.PeerCertificates) > 0 {
			cert := tlsState.PeerCertificates[0]
			tlsInfo.Issuer = cert.Issuer.CommonName
			if tlsInfo.Issuer == "" {
				tlsInfo.Issuer = cert.Issuer.String()
			}
			tlsInfo.Subject = cert.Subject.CommonName
			tlsInfo.Expiry = cert.NotAfter.Format(time.RFC3339)
		}
		result.TLS = tlsInfo
	}

	return result, nil
}

func tlsVersionName(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", ver)
	}
}
