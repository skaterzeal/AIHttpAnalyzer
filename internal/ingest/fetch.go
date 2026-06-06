package ingest

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// maxFetchBody caps how much of a response body we read, so a hostile or huge
// target cannot exhaust memory during a scan.
const maxFetchBody = 5 << 20 // 5 MiB

// Fetcher performs live HTTP requests against targets. TLS verification is
// disabled because pentest targets routinely have invalid/self-signed certs;
// the goal is to observe responses, not to trust them.
type Fetcher struct {
	client  *http.Client
	headers map[string]string
}

// NewFetcher builds a Fetcher with the given per-request timeout and extra
// headers applied to every request.
func NewFetcher(timeout time.Duration, headers map[string]string) *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // pentest targets
			},
		},
		headers: headers,
	}
}

// Fetch issues a request and normalizes the response into asset.HTTPResponse.
func (f *Fetcher) Fetch(ctx context.Context, method, rawurl string) (*asset.HTTPResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawurl, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range f.headers {
		req.Header.Set(k, v)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBody))
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[lower(k)] = resp.Header.Get(k)
	}

	reqHeaders := make(map[string]string, len(f.headers))
	for k, v := range f.headers {
		reqHeaders[lower(k)] = v
	}

	return &asset.HTTPResponse{
		StatusCode:  resp.StatusCode,
		Headers:     headers,
		Body:        string(body),
		ContentType: headers["content-type"],
		SizeBytes:   len(body),
		Request: &asset.HTTPRequest{
			Method:  method,
			URL:     rawurl,
			Path:    req.URL.Path,
			Headers: reqHeaders,
		},
		Source: "direct",
	}, nil
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
