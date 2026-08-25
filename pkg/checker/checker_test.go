package checker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadURLs(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Test array of objects with "urls" field
	objsPath := filepath.Join(tempDir, "objs.json")
	objsData := `[{"urls": "https://example.com/1"}, {"urls": "https://example.com/2"}]`
	if err := os.WriteFile(objsPath, []byte(objsData), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	urls, err := ReadURLs(objsPath)
	if err != nil {
		t.Fatalf("ReadURLs failed for object array: %v", err)
	}
	if len(urls) != 2 || urls[0] != "https://example.com/1" || urls[1] != "https://example.com/2" {
		t.Errorf("Unexpected result from ReadURLs object array: %v", urls)
	}

	// 2. Test array of strings
	strsPath := filepath.Join(tempDir, "strs.json")
	strsData := `["https://example.com/a", "https://example.com/b"]`
	if err := os.WriteFile(strsPath, []byte(strsData), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	urls, err = ReadURLs(strsPath)
	if err != nil {
		t.Fatalf("ReadURLs failed for string array: %v", err)
	}
	if len(urls) != 2 || urls[0] != "https://example.com/a" || urls[1] != "https://example.com/b" {
		t.Errorf("Unexpected result from ReadURLs string array: %v", urls)
	}
}

func TestCategorizeStatus(t *testing.T) {
	tests := []struct {
		code     int
		err      error
		expected string
	}{
		{200, nil, "OK"},
		{301, nil, "3xx Redirect"},
		{404, nil, "4xx Client Error"},
		{500, nil, "5xx Server Error"},
		{0, errors.New("connection timeout"), "ERROR"},
	}

	for _, tt := range tests {
		cat := CategorizeStatus(tt.code, tt.err)
		if cat != tt.expected {
			t.Errorf("CategorizeStatus(%d, %q) = %s; expected %s", tt.code, tt.err, cat, tt.expected)
		}
	}
}
