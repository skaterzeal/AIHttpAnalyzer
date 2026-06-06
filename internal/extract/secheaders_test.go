package extract

import (
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func sevByTitle(fs []asset.Finding, title string) (asset.Severity, bool) {
	for _, f := range fs {
		if f.Title == title {
			return f.Severity, true
		}
	}
	return "", false
}

func TestSecHeadersHTMLMissingAll(t *testing.T) {
	e := NewSecurityHeaderExtractor()
	r := &asset.HTTPResponse{
		StatusCode:  200,
		ContentType: "text/html; charset=utf-8",
		Headers:     map[string]string{},
		Request:     &asset.HTTPRequest{URL: "https://site/"},
	}
	fs := e.Extract(r)
	for _, want := range []string{
		"Missing Content-Security-Policy",
		"Missing X-Frame-Options",
		"Missing X-Content-Type-Options",
		"Missing Strict-Transport-Security",
	} {
		if _, ok := sevByTitle(fs, want); !ok {
			t.Errorf("expected %q on bare HTML response", want)
		}
	}
}

func TestSecHeadersJSONIsQuiet(t *testing.T) {
	// A JSON API with nosniff must NOT be flagged for CSP/X-Frame (FP control).
	e := NewSecurityHeaderExtractor()
	r := &asset.HTTPResponse{
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     map[string]string{"x-content-type-options": "nosniff"},
		Request:     &asset.HTTPRequest{URL: "https://api/x"},
	}
	fs := e.Extract(r)
	for _, unwanted := range []string{"Missing Content-Security-Policy", "Missing X-Frame-Options", "Missing X-Content-Type-Options"} {
		if _, ok := sevByTitle(fs, unwanted); ok {
			t.Errorf("JSON API should not report %q", unwanted)
		}
	}
}

func TestSecHeadersDangerousCORS(t *testing.T) {
	e := NewSecurityHeaderExtractor()
	r := &asset.HTTPResponse{
		StatusCode:  200,
		ContentType: "application/json",
		Headers: map[string]string{
			"x-content-type-options":           "nosniff",
			"access-control-allow-origin":      "*",
			"access-control-allow-credentials": "true",
		},
		Request: &asset.HTTPRequest{URL: "https://api/x"},
	}
	sev, ok := sevByTitle(e.Extract(r), "Permissive CORS with credentials")
	if !ok || sev != asset.SeverityHigh {
		t.Errorf("ACAO:* + credentials should be HIGH, got %v ok=%v", sev, ok)
	}
}

func TestSecHeadersSkipsErrorPages(t *testing.T) {
	e := NewSecurityHeaderExtractor()
	r := &asset.HTTPResponse{StatusCode: 404, ContentType: "text/html", Headers: map[string]string{}}
	if fs := e.Extract(r); len(fs) != 0 {
		t.Errorf("error pages should not produce header findings, got %v", fs)
	}
}
