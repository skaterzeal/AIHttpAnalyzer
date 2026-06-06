package extract

import (
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func TestEndpointExtractionRealPaths(t *testing.T) {
	e := NewEndpointExtractor()
	body := `{"endpoint":"/api/v2/users","data":[]}` +
		`<a href="/admin/login">x</a>` +
		`fetch("/api/internal/config")`
	r := &asset.HTTPResponse{Body: body, Headers: map[string]string{}}
	got := e.Extract(r)

	want := map[string]bool{"/api/v2/users": true, "/admin/login": true, "/api/internal/config": true}
	for w := range want {
		if !containsStr(got, w) {
			t.Errorf("expected endpoint %q in %v", w, got)
		}
	}
}

func TestEndpointFiltersFilesystemPaths(t *testing.T) {
	e := NewEndpointExtractor()
	// These appear in stack traces and env dumps — they are NOT endpoints.
	body := `"/home/app/views.py" "/usr/local/bin" "/opt/java" "/var/www/config" "/etc/passwd"`
	r := &asset.HTTPResponse{Body: body, Headers: map[string]string{}}
	got := e.Extract(r)
	for _, fp := range []string{"/home/app/views.py", "/usr/local/bin", "/opt/java", "/var/www/config", "/etc/passwd"} {
		if containsStr(got, fp) {
			t.Errorf("filesystem path %q should be filtered, got %v", fp, got)
		}
	}
}

func TestEndpointBlocklist(t *testing.T) {
	e := NewEndpointExtractor()
	r := &asset.HTTPResponse{Body: `{"url":"/","href":"//"}`, Headers: map[string]string{}}
	if got := e.Extract(r); len(got) != 0 {
		t.Errorf("expected no endpoints, got %v", got)
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
