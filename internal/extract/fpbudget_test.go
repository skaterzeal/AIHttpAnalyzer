package extract

import (
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// TestFalsePositiveBudgetCleanResponse anchors the tool's low-noise promise: a
// well-behaved JSON API response must produce zero findings. If a future
// pattern change starts flagging clean traffic, this test fails.
func TestFalsePositiveBudgetCleanResponse(t *testing.T) {
	e := newEngine(t)
	ar := e.Analyze(loadFixture(t, "clean_api.http"))

	if len(ar.Findings) != 0 {
		t.Errorf("clean API response should yield 0 findings, got %d: %+v", len(ar.Findings), ar.Findings)
	}
	if len(ar.Endpoints) != 0 {
		t.Errorf("clean API response should yield 0 endpoints, got %v", ar.Endpoints)
	}
}

// TestNoHighCriticalOnBenignHTML ensures an ordinary HTML page (missing some
// headers) only produces low/info findings — never high/critical noise.
func TestNoHighCriticalOnBenignHTML(t *testing.T) {
	e := newEngine(t)
	r := &asset.HTTPResponse{
		StatusCode:  200,
		ContentType: "text/html",
		Headers:     map[string]string{},
		Body:        "<html><body><h1>Welcome</h1></body></html>",
		Request:     &asset.HTTPRequest{URL: "https://site/"},
	}
	for _, f := range e.Analyze(r).Findings {
		if f.Severity == asset.SeverityHigh || f.Severity == asset.SeverityCritical {
			t.Errorf("benign HTML produced high/critical finding: %+v", f)
		}
	}
}
