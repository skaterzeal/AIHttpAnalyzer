package ingest

import (
	"path/filepath"
	"testing"
)

func TestParseBurpFixture(t *testing.T) {
	path := filepath.Join("..", "..", "tests", "fixtures", "burp_export.xml")
	resps, err := ParseBurpFile(path)
	if err != nil {
		t.Fatalf("ParseBurpFile: %v", err)
	}
	if len(resps) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(resps))
	}

	first := resps[0]
	if first.StatusCode != 200 {
		t.Errorf("first status = %d, want 200", first.StatusCode)
	}
	if first.Headers["server"] != "nginx/1.24.0" {
		t.Errorf("first server header = %q", first.Headers["server"])
	}
	if first.Request == nil || first.Request.URL != "https://example.com/api/v1/users" {
		t.Errorf("first request URL not parsed: %+v", first.Request)
	}
	if first.Source != "burp" {
		t.Errorf("source = %q, want burp", first.Source)
	}

	second := resps[1]
	if second.StatusCode != 500 {
		t.Errorf("second status = %d, want 500", second.StatusCode)
	}
	if !contains(second.Body, "Traceback") {
		t.Errorf("second body missing traceback: %q", second.Body)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestLoadDirFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "tests", "fixtures", "sample_responses")
	resps, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(resps) < 4 {
		t.Errorf("expected >=4 .http fixtures, got %d", len(resps))
	}
}
