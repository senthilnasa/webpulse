package export

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"

	"github.com/senthilnasa/webpulse/pkg/engine"
	"github.com/senthilnasa/webpulse/pkg/plugins"
)

func TestGenerateExports(t *testing.T) {
	results := []*engine.TargetResult{
		{
			SchemaVersion: 1,
			JobID:         "job-export-test",
			URL:           "https://example.com",
			Timestamp:     time.Now(),
			Status:        "completed",
			Target: engine.TargetMeta{
				URL:        "https://example.com",
				Hostname:   "example.com",
				ResolvedIP: "93.184.216.34",
				Port:       443,
				Protocol:   "https",
			},
			Response: engine.ResponseMeta{
				HTTPStatus:  200,
				StatusText:  "200 OK",
				TotalTimeMS: 120,
				SizeBytes:   1250,
				ContentType: "text/html",
			},
			Diagnostics: plugins.DiagnosticsResult{
				DNSLookupMS:  10,
				TCPConnectMS: 20,
				HTTPTTFBMS:   50,
			},
			Routing: plugins.RoutingResult{
				Hostname:           "example.com",
				DNSIP:              "104.20.23.154",
				OverrideIP:         "93.184.216.34",
				ActualConnectionIP: "93.184.216.34",
				HostHeader:         "example.com",
				TLSSNI:             "example.com",
				IsOverrideActive:   true,
			},
			Security: engine.SecurityMeta{
				SSRFValidated:   true,
				ScopeAuthorized: true,
			},
		},
	}

	// 1. JSON Export
	jsonBytes, err := GenerateJSON(results)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	if !bytes.Contains(jsonBytes, []byte("https://example.com")) {
		t.Error("JSON export missing target URL")
	}

	// 2. CSV Export
	csvBytes, err := GenerateCSV(results)
	if err != nil {
		t.Fatalf("GenerateCSV failed: %v", err)
	}
	if !bytes.Contains(csvBytes, []byte("URL,Status,HTTP Status")) {
		t.Error("CSV export missing header")
	}
	if !bytes.Contains(csvBytes, []byte("93.184.216.34")) {
		t.Error("CSV export missing override IP column data")
	}

	// 3. ZIP Export
	zipBytes, err := GenerateZIP("job-export-test", "standard", results)
	if err != nil {
		t.Fatalf("GenerateZIP failed: %v", err)
	}
	r, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("Failed to parse generated ZIP: %v", err)
	}

	foundJson, foundCsv, foundMeta := false, false, false
	for _, f := range r.File {
		if f.Name == "results.json" {
			foundJson = true
		}
		if f.Name == "results.csv" {
			foundCsv = true
		}
		if f.Name == "metadata.json" {
			foundMeta = true
		}
	}

	if !foundJson || !foundCsv || !foundMeta {
		t.Errorf("ZIP bundle missing files: json=%v, csv=%v, meta=%v", foundJson, foundCsv, foundMeta)
	}
}

func TestReadURLsInput(t *testing.T) {
	// TXT Input
	txtContent := []byte("https://example.com\nhttps://example.org\n# Comment\n\nhttps://api.example.com")
	urlsTxt, err := ReadURLsInput(txtContent, "urls.txt")
	if err != nil {
		t.Fatalf("ReadURLsInput TXT failed: %v", err)
	}
	if len(urlsTxt) != 3 {
		t.Errorf("Expected 3 URLs from TXT, got %d", len(urlsTxt))
	}

	// JSON Input
	jsonContent := []byte(`["https://example.com", "https://example.org"]`)
	urlsJson, err := ReadURLsInput(jsonContent, "urls.json")
	if err != nil {
		t.Fatalf("ReadURLsInput JSON failed: %v", err)
	}
	if len(urlsJson) != 2 {
		t.Errorf("Expected 2 URLs from JSON, got %d", len(urlsJson))
	}

	// CSV Input
	csvContent := []byte("url,status\nhttps://example.com,active\nhttps://example.org,active")
	urlsCsv, err := ReadURLsInput(csvContent, "urls.csv")
	if err != nil {
		t.Fatalf("ReadURLsInput CSV failed: %v", err)
	}
	if len(urlsCsv) != 2 {
		t.Errorf("Expected 2 URLs from CSV, got %d", len(urlsCsv))
	}
}

func TestParseHostsFile(t *testing.T) {
	// 1. Standard /etc/hosts format
	hostsContent := []byte("# Hosts mapping test\n93.184.216.34 example.com www.example.com\n10.20.30.40 api.example.com\n")
	resMap, err := ParseHostsFile(hostsContent)
	if err != nil {
		t.Fatalf("ParseHostsFile failed for /etc/hosts format: %v", err)
	}
	if resMap["example.com"] != "93.184.216.34" {
		t.Errorf("Expected example.com -> 93.184.216.34, got %s", resMap["example.com"])
	}
	if resMap["api.example.com"] != "10.20.30.40" {
		t.Errorf("Expected api.example.com -> 10.20.30.40, got %s", resMap["api.example.com"])
	}

	// 2. CSV format
	csvHosts := []byte("hostname,ip\nexample.com,93.184.216.34\napi.example.com,10.20.30.40")
	csvMap, err := ParseHostsFile(csvHosts)
	if err != nil {
		t.Fatalf("ParseHostsFile failed for CSV format: %v", err)
	}
	if csvMap["example.com"] != "93.184.216.34" {
		t.Errorf("CSV map missing example.com: %v", csvMap)
	}

	// 3. JSON Map format
	jsonHosts := []byte(`{"example.com": "93.184.216.34"}`)
	jsonMap, err := ParseHostsFile(jsonHosts)
	if err != nil {
		t.Fatalf("ParseHostsFile failed for JSON format: %v", err)
	}
	if jsonMap["example.com"] != "93.184.216.34" {
		t.Errorf("JSON map missing example.com: %v", jsonMap)
	}
}
