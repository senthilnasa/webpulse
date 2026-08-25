package checker

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReadURLs reads and parses a list of URLs from a JSON file.
// It supports:
// - An array of objects: [{"urls": "https://..."}, {"url": "https://..."}]
// - An array of strings: ["https://...", ...]
// - An object containing an array: {"urls": [...]}, {"url": [...]}
func ReadURLs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file %s: %w", path, err)
	}

	var rawItems []json.RawMessage
	if err := json.Unmarshal(data, &rawItems); err == nil {
		var urls []string
		for idx, item := range rawItems {
			// 1. Try plain string
			var strURL string
			if err := json.Unmarshal(item, &strURL); err == nil {
				if strURL != "" {
					urls = append(urls, strURL)
				}
				continue
			}

			// 2. Try JSON object with expected key ("urls", "url", "link", etc.)
			var objMap map[string]interface{}
			if err := json.Unmarshal(item, &objMap); err == nil {
				found := false
				for _, key := range []string{"urls", "url", "link", "target"} {
					if val, ok := objMap[key]; ok {
						if strVal, ok := val.(string); ok && strVal != "" {
							urls = append(urls, strVal)
							found = true
							break
						}
					}
				}
				if found {
					continue
				}
			}
			return nil, fmt.Errorf("item at index %d could not be parsed as a URL string or object containing a 'urls'/'url' field", idx)
		}
		return urls, nil
	}

	// 3. Try object wrapping an array field
	var objWrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &objWrapper); err == nil {
		for _, key := range []string{"urls", "url", "links", "targets"} {
			if rawArr, ok := objWrapper[key]; ok {
				var strList []string
				if err := json.Unmarshal(rawArr, &strList); err == nil {
					return strList, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("unsupported JSON structure in file %s", path)
}
