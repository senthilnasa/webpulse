package egress

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

type mockRoundTripper struct {
	responseBody string
	statusCode   int
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(m.responseBody)),
		Header:     make(http.Header),
	}, nil
}

func TestFetchPublicIP(t *testing.T) {
	mockClient := &http.Client{
		Transport: &mockRoundTripper{
			responseBody: "203.0.113.195\n",
			statusCode:   http.StatusOK,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ip, err := FetchPublicIPWithClient(ctx, mockClient, "https://api.ipify.org")
	if err != nil {
		t.Fatalf("Unexpected error fetching public IP: %v", err)
	}

	if ip != "203.0.113.195" {
		t.Errorf("Expected IP 203.0.113.195, got %s", ip)
	}
}
