package export

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/senthilnasa/webpulse/pkg/engine"
)

// GenerateJSON returns pretty-printed JSON byte slice conforming to canonical schema.
func GenerateJSON(results []*engine.TargetResult) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}

// GenerateCSV converts target results into CSV byte array including routing and override columns.
func GenerateCSV(results []*engine.TargetResult) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	headers := []string{
		"URL",
		"Status",
		"HTTP Status",
		"Status Text",
		"Response Time (ms)",
		"Response Size (Bytes)",
		"Resolved IP",
		"DNS IP",
		"Override IP",
		"Actual Connection IP",
		"Is Override Active",
		"Protocol",
		"Port",
		"Content Type",
		"DNS Lookup (ms)",
		"TCP Connect (ms)",
		"TLS Handshake (ms)",
		"HTTP TTFB (ms)",
		"Redirect Count",
		"Redirect URLs",
		"TLS Version",
		"Cert Issuer",
		"SSRF Validated",
		"Scope Authorized",
		"Errors",
	}

	if err := writer.Write(headers); err != nil {
		return nil, err
	}

	for _, r := range results {
		errStr := ""
		if len(r.Errors) > 0 {
			errStr = strings.Join(r.Errors, "; ")
		}

		redirectURLsStr := ""
		if len(r.Response.Redirects) > 0 {
			redirectURLsStr = strings.Join(r.Response.Redirects, " -> ")
		}

		tlsVer, tlsIssuer := "", ""
		if r.TLS != nil {
			tlsVer = r.TLS.Version
			tlsIssuer = r.TLS.Issuer
		}

		row := []string{
			r.URL,
			r.Status,
			strconv.Itoa(r.Response.HTTPStatus),
			r.Response.StatusText,
			strconv.FormatInt(r.Response.TotalTimeMS, 10),
			strconv.FormatInt(r.Response.SizeBytes, 10),
			r.Target.ResolvedIP,
			r.Routing.DNSIP,
			r.Routing.OverrideIP,
			r.Routing.ActualConnectionIP,
			strconv.FormatBool(r.Routing.IsOverrideActive),
			r.Target.Protocol,
			strconv.Itoa(r.Target.Port),
			r.Response.ContentType,
			strconv.FormatInt(r.Diagnostics.DNSLookupMS, 10),
			strconv.FormatInt(r.Diagnostics.TCPConnectMS, 10),
			strconv.FormatInt(r.Diagnostics.TLSHandshakeMS, 10),
			strconv.FormatInt(r.Diagnostics.HTTPTTFBMS, 10),
			strconv.Itoa(len(r.Response.Redirects)),
			redirectURLsStr,
			tlsVer,
			tlsIssuer,
			strconv.FormatBool(r.Security.SSRFValidated),
			strconv.FormatBool(r.Security.ScopeAuthorized),
			errStr,
		}

		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	return buf.Bytes(), writer.Error()
}

// GenerateZIP creates an in-memory ZIP archive containing results.json, results.csv, and metadata.json.
func GenerateZIP(jobID string, profileName string, results []*engine.TargetResult) ([]byte, error) {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// 1. Write results.json
	jsonBytes, err := GenerateJSON(results)
	if err != nil {
		return nil, err
	}
	fJson, err := zipWriter.Create("results.json")
	if err != nil {
		return nil, err
	}
	if _, err := fJson.Write(jsonBytes); err != nil {
		return nil, err
	}

	// 2. Write results.csv
	csvBytes, err := GenerateCSV(results)
	if err != nil {
		return nil, err
	}
	fCsv, err := zipWriter.Create("results.csv")
	if err != nil {
		return nil, err
	}
	if _, err := fCsv.Write(csvBytes); err != nil {
		return nil, err
	}

	// 3. Write metadata.json
	metadata := map[string]interface{}{
		"job_id":       jobID,
		"profile":      profileName,
		"generated_at": time.Now().Format(time.RFC3339),
		"total_urls":   len(results),
	}
	metaBytes, _ := json.MarshalIndent(metadata, "", "  ")
	fMeta, err := zipWriter.Create("metadata.json")
	if err != nil {
		return nil, err
	}
	if _, err := fMeta.Write(metaBytes); err != nil {
		return nil, err
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ParseHostsFile parses /etc/hosts format, CSV (hostname,ip), or JSON resolutions into map[hostname]ip.
func ParseHostsFile(content []byte) (map[string]string, error) {
	resolutions := make(map[string]string)

	// 1. Try JSON map or JSON array
	var jsonMap map[string]string
	if err := json.Unmarshal(content, &jsonMap); err == nil && len(jsonMap) > 0 {
		for k, v := range jsonMap {
			resolutions[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
		return resolutions, nil
	}

	var jsonArr []map[string]string
	if err := json.Unmarshal(content, &jsonArr); err == nil && len(jsonArr) > 0 {
		for _, item := range jsonArr {
			host := item["hostname"]
			if host == "" {
				host = item["host"]
			}
			ip := item["ip"]
			if host != "" && ip != "" {
				resolutions[strings.ToLower(strings.TrimSpace(host))] = strings.TrimSpace(ip)
			}
		}
		return resolutions, nil
	}

	// 2. Try CSV format (hostname,ip or ip,hostname)
	reader := csv.NewReader(bytes.NewReader(content))
	records, err := reader.ReadAll()
	if err == nil && len(records) > 0 {
		startRow := 0
		hostCol, ipCol := 0, 1
		firstRow := records[0]
		if len(firstRow) >= 2 {
			if strings.ToLower(firstRow[0]) == "hostname" || strings.ToLower(firstRow[0]) == "host" {
				hostCol, ipCol = 0, 1
				startRow = 1
			} else if strings.ToLower(firstRow[0]) == "ip" {
				ipCol, hostCol = 0, 1
				startRow = 1
			}
		}
		for i := startRow; i < len(records); i++ {
			row := records[i]
			if len(row) >= 2 {
				h := strings.ToLower(strings.TrimSpace(row[hostCol]))
				ip := strings.TrimSpace(row[ipCol])
				if h != "" && ip != "" {
					resolutions[h] = ip
				}
			}
		}
		if len(resolutions) > 0 {
			return resolutions, nil
		}
	}

	// 3. Fallback: Standard /etc/hosts format (IP Hostname1 Hostname2 ...)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			ip := fields[0]
			for idx := 1; idx < len(fields); idx++ {
				h := strings.ToLower(fields[idx])
				if !strings.HasPrefix(h, "#") {
					resolutions[h] = ip
				}
			}
		}
	}

	return resolutions, nil
}

// ReadURLsInput parses a TXT, CSV, or JSON string/reader into a slice of raw URL strings.
func ReadURLsInput(content []byte, filename string) ([]string, error) {
	filenameLower := strings.ToLower(filename)

	// JSON format
	if strings.HasSuffix(filenameLower, ".json") || bytes.HasPrefix(bytes.TrimSpace(content), []byte("[")) {
		var urls []string
		if err := json.Unmarshal(content, &urls); err == nil {
			return cleanURLList(urls), nil
		}
		var objects []map[string]interface{}
		if err := json.Unmarshal(content, &objects); err == nil {
			for _, obj := range objects {
				if u, ok := obj["url"].(string); ok {
					urls = append(urls, u)
				} else if u, ok := obj["urls"].(string); ok {
					urls = append(urls, u)
				}
			}
			return cleanURLList(urls), nil
		}
	}

	// CSV format
	if strings.HasSuffix(filenameLower, ".csv") {
		reader := csv.NewReader(bytes.NewReader(content))
		records, err := reader.ReadAll()
		if err == nil && len(records) > 0 {
			var urls []string
			urlCol := 0
			for idx, header := range records[0] {
				if strings.ToLower(strings.TrimSpace(header)) == "url" {
					urlCol = idx
					break
				}
			}
			startRow := 0
			if strings.ToLower(records[0][urlCol]) == "url" {
				startRow = 1
			}
			for i := startRow; i < len(records); i++ {
				if urlCol < len(records[i]) {
					urls = append(urls, records[i][urlCol])
				}
			}
			return cleanURLList(urls), nil
		}
	}

	// TXT format (one URL per line)
	lines := strings.Split(string(content), "\n")
	return cleanURLList(lines), nil
}

func cleanURLList(raw []string) []string {
	var cleaned []string
	seen := make(map[string]bool)

	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			cleaned = append(cleaned, trimmed)
		}
	}

	return cleaned
}
