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

// GenerateCSV converts target results into CSV byte array.
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
		"Protocol",
		"Port",
		"Content Type",
		"DNS Lookup (ms)",
		"TCP Connect (ms)",
		"TLS Handshake (ms)",
		"HTTP TTFB (ms)",
		"Redirect Count",
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
			r.Target.Protocol,
			strconv.Itoa(r.Target.Port),
			r.Response.ContentType,
			strconv.FormatInt(r.Diagnostics.DNSLookupMS, 10),
			strconv.FormatInt(r.Diagnostics.TCPConnectMS, 10),
			strconv.FormatInt(r.Diagnostics.TLSHandshakeMS, 10),
			strconv.FormatInt(r.Diagnostics.HTTPTTFBMS, 10),
			strconv.Itoa(len(r.Response.Redirects)),
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

// ReadURLsInput parses a TXT, CSV, or JSON string/reader into a slice of raw URL strings.
func ReadURLsInput(content []byte, filename string) ([]string, error) {
	filenameLower := strings.ToLower(filename)

	// JSON format
	if strings.HasSuffix(filenameLower, ".json") || bytes.HasPrefix(bytes.TrimSpace(content), []byte("[")) {
		var urls []string
		if err := json.Unmarshal(content, &urls); err == nil {
			return cleanURLList(urls), nil
		}
		// Or JSON array of objects with "url" or "urls" field
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
			// Find column index named "url" if present
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
