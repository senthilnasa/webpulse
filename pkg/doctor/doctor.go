package doctor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/senthilnasa/webpulse/pkg/egress"
)

// CheckItem represents a single system diagnostic check.
type CheckItem struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

// DoctorReport aggregates system connectivity status.
type DoctorReport struct {
	PublicIPv4  string      `json:"public_ipv4"`
	PublicIPv6  string      `json:"public_ipv6"`
	Ready       bool        `json:"ready_for_testing"`
	Checks      []CheckItem `json:"checks"`
	EgressInfo  *egress.EgressInfo `json:"egress_info,omitempty"`
}

// RunDoctor performs diagnostic checks on network, DNS, TLS, and egress IP.
func RunDoctor(ctx context.Context) *DoctorReport {
	report := &DoctorReport{
		Ready: true,
	}

	// 1. Egress IP Check
	egressInfo, _ := egress.DetectEgressInfo(ctx, true)
	if egressInfo != nil {
		report.EgressInfo = egressInfo
		report.PublicIPv4 = egressInfo.IPv4
		report.PublicIPv6 = egressInfo.IPv6

		if egressInfo.IPv4 != "" {
			report.Checks = append(report.Checks, CheckItem{
				Name:    "Public IPv4",
				Passed:  true,
				Details: egressInfo.IPv4,
			})
		} else {
			report.Checks = append(report.Checks, CheckItem{
				Name:    "Public IPv4",
				Passed:  false,
				Details: "Unable to detect public IPv4 address",
			})
		}
	}

	// 2. DNS Resolution Check
	resolverCtx, cancel1 := context.WithTimeout(ctx, 3*time.Second)
	defer cancel1()
	ips, err := net.DefaultResolver.LookupHost(resolverCtx, "example.com")
	if err == nil && len(ips) > 0 {
		report.Checks = append(report.Checks, CheckItem{
			Name:    "DNS Resolution",
			Passed:  true,
			Details: fmt.Sprintf("Resolved example.com to %v", ips[0]),
		})
	} else {
		report.Ready = false
		report.Checks = append(report.Checks, CheckItem{
			Name:    "DNS Resolution",
			Passed:  false,
			Details: fmt.Sprintf("DNS lookup failed: %v", err),
		})
	}

	// 3. Outbound HTTP Check
	httpCtx, cancel2 := context.WithTimeout(ctx, 4*time.Second)
	defer cancel2()
	httpReq, _ := http.NewRequestWithContext(httpCtx, http.MethodHead, "http://example.com", nil)
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(httpReq)
	if err == nil {
		resp.Body.Close()
		report.Checks = append(report.Checks, CheckItem{
			Name:    "Outbound HTTP",
			Passed:  true,
			Details: fmt.Sprintf("Status %d OK", resp.StatusCode),
		})
	} else {
		report.Checks = append(report.Checks, CheckItem{
			Name:    "Outbound HTTP",
			Passed:  false,
			Details: fmt.Sprintf("HTTP probe failed: %v", err),
		})
	}

	// 4. Outbound HTTPS & TLS Check
	httpsCtx, cancel3 := context.WithTimeout(ctx, 4*time.Second)
	defer cancel3()
	httpsReq, _ := http.NewRequestWithContext(httpsCtx, http.MethodHead, "https://example.com", nil)
	httpsResp, err := client.Do(httpsReq)
	if err == nil {
		httpsResp.Body.Close()
		report.Checks = append(report.Checks, CheckItem{
			Name:    "Outbound HTTPS / TLS",
			Passed:  true,
			Details: fmt.Sprintf("Status %d OK", httpsResp.StatusCode),
		})
	} else {
		report.Checks = append(report.Checks, CheckItem{
			Name:    "Outbound HTTPS / TLS",
			Passed:  false,
			Details: fmt.Sprintf("HTTPS probe failed: %v", err),
		})
	}

	return report
}

// PrintTerminalReport outputs a human-readable diagnostic report.
func (dr *DoctorReport) PrintTerminalReport() {
	fmt.Println("\nWebTest Doctor")
	fmt.Println("────────────────────────────────────────")
	for _, check := range dr.Checks {
		symbol := "✓"
		if !check.Passed {
			symbol = "✗"
		}
		fmt.Printf("%-20s %s  %s\n", check.Name, symbol, check.Details)
	}

	fmt.Println("────────────────────────────────────────")
	if dr.PublicIPv4 != "" {
		fmt.Printf("Egress IP:           %s\n", dr.PublicIPv4)
	} else {
		fmt.Println("Egress IP:           Unknown")
	}

	readyText := "YES"
	if !dr.Ready {
		readyText = "NO (Network/DNS issues detected)"
	}
	fmt.Printf("Ready for testing:   %s\n\n", readyText)
}
