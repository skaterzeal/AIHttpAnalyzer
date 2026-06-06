// Package httpparse converts raw HTTP request/response text blocks into the
// shared asset domain types. It is intentionally lenient: real-world captures
// (Burp exports, saved .http files, proxy dumps) are frequently malformed, and
// a triage tool must extract whatever signal it can rather than reject input.
package httpparse

import (
	"strconv"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// splitHeaderBody separates the header block from the body, tolerating both
// CRLF and LF separators. If no blank-line separator is present the whole input
// is treated as headers with an empty body.
func splitHeaderBody(raw string) (header, body string) {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, ""
}

// parseHeaders parses "Key: Value" lines, lowercasing keys for stable lookup.
// The first line (request/status line) is expected to be stripped by the caller.
func parseHeaders(lines []string) map[string]string {
	headers := make(map[string]string)
	for _, line := range lines {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return headers
}

// ParseResponse parses a raw HTTP response into an asset.HTTPResponse. source
// labels where the capture came from ("file", "burp", "proxy", ...).
func ParseResponse(responseRaw, source string) *asset.HTTPResponse {
	header, body := splitHeaderBody(responseRaw)
	lines := strings.Split(header, "\n")

	statusCode := 0
	if len(lines) > 0 {
		// Status line: "HTTP/1.1 200 OK" -> the second token is the code.
		parts := strings.Fields(strings.TrimSpace(lines[0]))
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				statusCode = code
			}
		}
	}

	var headerLines []string
	if len(lines) > 1 {
		headerLines = lines[1:]
	}
	headers := parseHeaders(headerLines)

	return &asset.HTTPResponse{
		StatusCode:  statusCode,
		Headers:     headers,
		Body:        body,
		ContentType: headers["content-type"],
		SizeBytes:   len(body),
		Source:      source,
	}
}

// ParseRequest parses a raw HTTP request into an asset.HTTPRequest. url is the
// absolute URL when known (e.g. from a Burp item); the path is taken from the
// request line. Returns nil for empty input.
func ParseRequest(requestRaw, url string) *asset.HTTPRequest {
	if strings.TrimSpace(requestRaw) == "" {
		return nil
	}
	header, body := splitHeaderBody(requestRaw)
	lines := strings.Split(header, "\n")

	method, path := "GET", "/"
	if len(lines) > 0 {
		parts := strings.Fields(strings.TrimSpace(lines[0]))
		if len(parts) > 0 {
			method = parts[0]
		}
		if len(parts) > 1 {
			path = parts[1]
		}
	}

	var headerLines []string
	if len(lines) > 1 {
		headerLines = lines[1:]
	}
	headers := parseHeaders(headerLines)

	return &asset.HTTPRequest{
		Method:  method,
		URL:     url,
		Path:    path,
		Headers: headers,
		Body:    strings.TrimSpace(body),
	}
}
