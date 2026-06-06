package correlate

import (
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func TestDedupeFindings(t *testing.T) {
	in := []asset.Finding{
		{Asset: "a", Type: asset.FindingMisconfig, Title: "Missing CSP"},
		{Asset: "a", Type: asset.FindingMisconfig, Title: "Missing CSP"},
		{Asset: "b", Type: asset.FindingMisconfig, Title: "Missing CSP"},
	}
	out := DedupeFindings(in)
	if len(out) != 2 {
		t.Errorf("expected 2 after dedupe, got %d", len(out))
	}
}

func TestBuildMapAggregates(t *testing.T) {
	results := []asset.AnalyzedResponse{
		{
			Response:     &asset.HTTPResponse{Request: &asset.HTTPRequest{URL: "https://example.com/a"}},
			Endpoints:    []string{"/api/v1", "/admin"},
			Technologies: []string{"Django"},
			Findings: []asset.Finding{
				{Asset: "https://example.com/a", Type: asset.FindingVersionDisclosure, Severity: asset.SeverityCritical, Title: "apache 2.4.49", CVE: []string{"CVE-2021-42013"}, CVSS: 9.8},
			},
		},
		{
			Response:     &asset.HTTPResponse{Request: &asset.HTTPRequest{URL: "https://example.com/b"}},
			Endpoints:    []string{"/api/v1"}, // duplicate endpoint
			Technologies: []string{"nginx"},
			Findings: []asset.Finding{
				{Asset: "https://example.com/b", Type: asset.FindingErrorMessage, Severity: asset.SeverityLow, Title: "minor"},
			},
		},
	}
	m := BuildMap(results)

	if m.Target != "example.com" {
		t.Errorf("target = %q, want example.com", m.Target)
	}
	if len(m.UniqueEndpoints) != 2 {
		t.Errorf("expected 2 unique endpoints, got %v", m.UniqueEndpoints)
	}
	if len(m.Technologies) != 2 {
		t.Errorf("expected 2 technologies, got %v", m.Technologies)
	}
	if len(m.CVEs) != 1 || m.CVEs[0] != "CVE-2021-42013" {
		t.Errorf("expected 1 CVE, got %v", m.CVEs)
	}
	if len(m.CriticalFindings) != 1 {
		t.Errorf("expected 1 high/critical finding, got %d", len(m.CriticalFindings))
	}
}
