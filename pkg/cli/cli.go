package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/senthilnasa/webpulse/pkg/doctor"
	"github.com/senthilnasa/webpulse/pkg/egress"
	"github.com/senthilnasa/webpulse/pkg/engine"
	"github.com/senthilnasa/webpulse/pkg/export"
	"github.com/senthilnasa/webpulse/pkg/scope"
	"github.com/senthilnasa/webpulse/pkg/ssrf"
)

const Version = "1.0.0"

func Execute(args []string) {
	if len(args) < 2 {
		printUsage()
		os.Exit(0)
	}

	command := strings.ToLower(args[1])

	switch command {
	case "scan":
		runScanCommand(args[2:])
	case "doctor":
		runDoctorCommand()
	case "version", "-v", "--version":
		runVersionCommand()
	case "help", "-h", "--help":
		printUsage()
	default:
		if strings.HasPrefix(command, "http://") || strings.HasPrefix(command, "https://") || strings.Contains(command, ".") {
			runScanCommand(args[1:])
		} else {
			fmt.Printf("Unknown command: %s\n\n", command)
			printUsage()
			os.Exit(2)
		}
	}
}

func printUsage() {
	fmt.Println(`WebPulse — Authorized Web Testing & Diagnostics CLI

Usage:
  webpulse scan <url|file> [flags]
  webpulse doctor
  webpulse version

Commands:
  scan     Execute diagnostic HTTP probes against a target URL or bulk file (TXT, CSV, JSON)
  doctor   Diagnose local network, DNS, TLS, and public egress IP connectivity
  version  Display WebPulse CLI version and egress IP info

Flags for scan:
  -p, --profile           Test profile: quick, standard, comprehensive (default "standard")
  -w, --workers           Number of concurrent worker goroutines
  -t, --timeout           Timeout per HTTP request in seconds
  -f, --format            Output format: table, json, csv (default "table")
  -o, --output            Output file path (e.g. results.json or results.csv)
  --resolve               Target IP override (e.g. example.com:198.51.100.50 or 198.51.100.50:example.com)
  --hosts-file            Path to hosts resolution file (/etc/hosts, CSV, JSON)
  --allow-private-targets Permit testing authorized private/staging IP ranges (requires explicit policy)
  --dry-run               Perform scope & SSRF validation without dialing targets
  --fail-on-error         Exit with code 1 if any target failed or was blocked

Examples:
  webpulse scan https://example.com --resolve example.com:198.51.100.50
  webpulse scan urls.txt --hosts-file ./hosts.test --workers 10
  webpulse scan urls.csv --format csv --output report.csv
  webpulse scan urls.json --dry-run
  webpulse doctor`)
}

func runVersionCommand() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fmt.Printf("WebPulse CLI v%s\n", Version)
	egressInfo, _ := egress.DetectEgressInfo(ctx, false)
	if egressInfo != nil && egressInfo.IPv4 != "" {
		fmt.Printf("Engine Egress Public IP: %s\n", egressInfo.IPv4)
	}
}

func runDoctorCommand() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report := doctor.RunDoctor(ctx)
	report.PrintTerminalReport()
	if !report.Ready {
		os.Exit(1)
	}
}

type resolveFlags []string

func (r *resolveFlags) String() string {
	return strings.Join(*r, ",")
}

func (r *resolveFlags) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func runScanCommand(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)

	var profileName, format, outputPath, allowedScope, hostsFilePath string
	var resolves resolveFlags
	var workers, timeoutSec int
	var dryRun, failOnError, allowPrivateTargets, allowInsecure bool

	fs.StringVar(&profileName, "profile", "standard", "Test profile: quick, standard, comprehensive")
	fs.StringVar(&profileName, "p", "standard", "Test profile (shorthand)")
	fs.IntVar(&workers, "workers", 0, "Number of concurrent workers")
	fs.IntVar(&workers, "w", 0, "Number of concurrent workers (shorthand)")
	fs.IntVar(&timeoutSec, "timeout", 0, "Timeout per request in seconds")
	fs.IntVar(&timeoutSec, "t", 0, "Timeout per request in seconds (shorthand)")
	fs.StringVar(&format, "format", "table", "Output format: table, json, csv")
	fs.StringVar(&format, "f", "table", "Output format (shorthand)")
	fs.StringVar(&outputPath, "output", "", "Output file path")
	fs.StringVar(&outputPath, "o", "", "Output file path (shorthand)")
	fs.Var(&resolves, "resolve", "Target IP Override resolution (e.g. example.com:198.51.100.50)")
	fs.StringVar(&hostsFilePath, "hosts-file", "", "Path to hosts resolution file")
	fs.BoolVar(&allowPrivateTargets, "allow-private-targets", false, "Permit testing authorized private/staging targets")
	fs.BoolVar(&allowInsecure, "insecure", false, "Allow self-signed or untrusted TLS certificates")
	fs.BoolVar(&allowInsecure, "k", false, "Allow self-signed or untrusted TLS certificates (shorthand)")
	fs.BoolVar(&dryRun, "dry-run", false, "Perform scope & SSRF validation without dialing targets")
	fs.BoolVar(&failOnError, "fail-on-error", false, "Exit with code 1 if any target failed or was blocked")
	fs.StringVar(&allowedScope, "scope", "", "Comma-separated allowed target domain glob patterns")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	targetInput := fs.Arg(0)
	if targetInput == "" {
		fmt.Println("Error: Target URL or input file path is required.")
		fmt.Println("Example: webpulse scan https://example.com --resolve example.com:198.51.100.50")
		os.Exit(2)
	}

	// 1. Resolve URLs from input
	var urls []string
	if strings.HasPrefix(targetInput, "http://") || strings.HasPrefix(targetInput, "https://") {
		urls = []string{targetInput}
	} else {
		content, err := os.ReadFile(targetInput)
		if err != nil {
			fmt.Printf("Error reading input file '%s': %v\n", targetInput, err)
			os.Exit(2)
		}
		parsedURLs, err := export.ReadURLsInput(content, targetInput)
		if err != nil {
			fmt.Printf("Error parsing input file '%s': %v\n", targetInput, err)
			os.Exit(2)
		}
		urls = parsedURLs
	}

	if len(urls) == 0 {
		fmt.Println("Error: No valid URLs found in input.")
		os.Exit(2)
	}

	// 2. Build Target IP Overrides map
	hostResolutions := make(map[string]string)

	if hostsFilePath != "" {
		content, err := os.ReadFile(hostsFilePath)
		if err != nil {
			fmt.Printf("Error reading hosts file '%s': %v\n", hostsFilePath, err)
			os.Exit(2)
		}
		parsedMap, err := export.ParseHostsFile(content)
		if err != nil {
			fmt.Printf("Error parsing hosts file '%s': %v\n", hostsFilePath, err)
			os.Exit(2)
		}
		for k, v := range parsedMap {
			hostResolutions[k] = v
		}
	}

	for _, item := range resolves {
		parts := strings.Split(item, ":")
		if len(parts) == 2 {
			p1, p2 := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			if ssrf.IsIPRestricted(nil) { // check string format
			}
			// Support both hostname:ip and ip:hostname
			if strings.Count(p1, ".") == 3 && strings.Count(p2, ".") != 3 { // ip:hostname
				hostResolutions[strings.ToLower(p2)] = p1
			} else { // hostname:ip
				hostResolutions[strings.ToLower(p1)] = p2
			}
		}
	}

	// 3. Build Profile & Scope Policy
	prof := engine.DefaultProfile(profileName)
	if workers > 0 {
		prof.Workers = workers
	}
	if timeoutSec > 0 {
		prof.Timeout = time.Duration(timeoutSec) * time.Second
	}
	prof.HostResolutions = hostResolutions
	prof.AllowPrivateTargets = allowPrivateTargets
	prof.AllowInsecure = allowInsecure

	var scopePolicy *scope.ScopePolicy
	if allowedScope != "" {
		patterns := strings.Split(allowedScope, ",")
		scopePolicy = &scope.ScopePolicy{AllowedPatterns: patterns}
	}

	eng := engine.NewEngine(scopePolicy)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Printf("\nWebPulse Scan | Targets: %d | Profile: %s | Workers: %d\n", len(urls), prof.Name, prof.Workers)
	if len(hostResolutions) > 0 {
		fmt.Println("⚠ TARGET IP OVERRIDE ACTIVE:")
		for h, ip := range hostResolutions {
			fmt.Printf("   %-30s → %s (Host: %s | SNI: %s)\n", h, ip, h, h)
		}
	}
	fmt.Println("Only test systems you own or have explicit authorization to test.")
	fmt.Println("─────────────────────────────────────────────────────────────────")

	// 4. Dry Run Execution
	if dryRun {
		fmt.Println("[DRY RUN MODE] Validating Scope & SSRF defenses...")
		hasFailures := false
		for idx, u := range urls {
			sanitized, err := ssrf.SanitizeURL(u)
			status := "PASS"
			reason := "Target URL valid"
			if err != nil && !allowPrivateTargets {
				status = "BLOCKED"
				reason = err.Error()
				hasFailures = true
			} else if scopePolicy != nil {
				val := scope.NewScopeValidator(*scopePolicy)
				if err := val.ValidateURL(u); err != nil {
					status = "BLOCKED"
					reason = err.Error()
					hasFailures = true
				}
			}
			fmt.Printf("[%d/%d] %-45s [%s] %s\n", idx+1, len(urls), u, status, reason)
			if sanitized != nil {
				_ = sanitized
			}
		}
		if hasFailures && failOnError {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 5. Perform Diagnostic Scan
	jobID := fmt.Sprintf("job-%d", time.Now().Unix())
	startTime := time.Now()

	results := eng.ExecuteJob(ctx, jobID, urls, prof, nil)
	duration := time.Since(startTime)

	// 6. Output Formatting & Save
	hasFailures := false
	completedCount, failedCount, blockedCount := 0, 0, 0

	for _, r := range results {
		switch r.Status {
		case "completed":
			completedCount++
		case "failed":
			failedCount++
			hasFailures = true
		case "blocked":
			blockedCount++
			hasFailures = true
		}
	}

	switch strings.ToLower(format) {
	case "json":
		jsonBytes, _ := export.GenerateJSON(results)
		if outputPath != "" {
			_ = os.WriteFile(outputPath, jsonBytes, 0644)
			fmt.Printf("Results saved to %s\n", outputPath)
		} else {
			fmt.Println(string(jsonBytes))
		}
	case "csv":
		csvBytes, _ := export.GenerateCSV(results)
		if outputPath != "" {
			_ = os.WriteFile(outputPath, csvBytes, 0644)
			fmt.Printf("Results saved to %s\n", outputPath)
		} else {
			fmt.Println(string(csvBytes))
		}
	default:
		printTerminalResults(results, duration, completedCount, failedCount, blockedCount)
		if outputPath != "" {
			if strings.HasSuffix(outputPath, ".csv") {
				csvBytes, _ := export.GenerateCSV(results)
				_ = os.WriteFile(outputPath, csvBytes, 0644)
			} else {
				jsonBytes, _ := export.GenerateJSON(results)
				_ = os.WriteFile(outputPath, jsonBytes, 0644)
			}
			fmt.Printf("\nSaved %d results to %s\n", len(results), outputPath)
		}
	}

	if hasFailures && failOnError {
		os.Exit(1)
	}
}

func printTerminalResults(results []*engine.TargetResult, duration time.Duration, completed, failed, blocked int) {
	fmt.Printf("\n%-40s %-8s %-8s %-12s %-15s %-10s\n", "TARGET URL", "STATUS", "HTTP", "LATENCY", "CONNECTED IP", "OVERRIDE")
	fmt.Println("───────────────────────────────────────────────────────────────────────────────────────────────────")

	for _, r := range results {
		statusPill := r.Status
		httpPill := fmt.Sprintf("%d", r.Response.HTTPStatus)
		if r.Response.HTTPStatus == 0 {
			httpPill = "-"
		}
		latencyPill := fmt.Sprintf("%dms", r.Response.TotalTimeMS)
		if r.Response.TotalTimeMS == 0 {
			latencyPill = "-"
		}
		ipPill := r.Target.ResolvedIP
		if ipPill == "" {
			ipPill = "-"
		}

		overridePill := "No"
		if r.Routing.IsOverrideActive {
			overridePill = "YES"
		}

		targetDisp := r.URL
		if len(targetDisp) > 38 {
			targetDisp = targetDisp[:35] + "..."
		}

		fmt.Printf("%-40s %-8s %-8s %-12s %-15s %-10s\n", targetDisp, statusPill, httpPill, latencyPill, ipPill, overridePill)
	}

	fmt.Println("───────────────────────────────────────────────────────────────────────────────────────────────────")
	fmt.Printf("Scan Finished in %v | Total: %d | Completed: %d | Failed: %d | Blocked: %d\n",
		duration.Round(time.Millisecond), len(results), completed, failed, blocked)
}
