package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func TestWriteHTMLContainsFindings(t *testing.T) {
	results := []asset.AnalyzedResponse{{
		Response: &asset.HTTPResponse{Request: &asset.HTTPRequest{URL: "https://x/a"}},
		Findings: []asset.Finding{{
			Asset: "https://x/a", Type: asset.FindingVersionDisclosure,
			Severity: asset.SeverityCritical, Title: "apache 2.4.49",
			CVE: []string{"CVE-2021-42013"}, CVSS: 9.8, Source: asset.SourceCVE,
		}},
		Technologies: []string{"Apache"},
	}}

	var buf bytes.Buffer
	if err := WriteHTML(&buf, results, asset.SeverityInfo); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<!DOCTYPE html>", "apache 2.4.49", "CVE-2021-42013", "Apache", "</html>"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestWriteHTMLEscapesContent(t *testing.T) {
	results := []asset.AnalyzedResponse{{
		Response: &asset.HTTPResponse{Request: &asset.HTTPRequest{URL: "https://x"}},
		Findings: []asset.Finding{{
			Asset: "https://x", Type: asset.FindingStackTrace, Severity: asset.SeverityHigh,
			Title: "trace", Evidence: "<script>alert(1)</script>",
		}},
	}}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, results, asset.SeverityInfo); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Error("evidence must be HTML-escaped to prevent report XSS")
	}
}
