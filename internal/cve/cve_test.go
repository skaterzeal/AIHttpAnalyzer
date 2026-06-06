package cve

import (
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.2", 0},
		{"2.4.49", "2.4.50", -1},
		{"2.4.51", "2.4.50", 1},
		{"1.21.0", "1.9.0", 1}, // numeric, not lexical
		{"1.0.1g", "1.0.1", 0}, // suffix ignored on numeric compare
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSatisfies(t *testing.T) {
	cases := []struct {
		v, c string
		want bool
	}{
		{"2.4.49", ">=2.4.49,<2.4.50", true},
		{"2.4.50", ">=2.4.49,<2.4.50", false},
		{"1.20.0", "<1.21.0", true},
		{"1.24.0", "<1.21.0", false},
		{"8.1.0", ">=8.1.0,<8.1.29", true},
		{"8.2.5", ">=8.1.0,<8.1.29", false},
	}
	for _, c := range cases {
		if got := satisfies(c.v, c.c); got != c.want {
			t.Errorf("satisfies(%q,%q) = %v, want %v", c.v, c.c, got, c.want)
		}
	}
}

func TestMatchEmbeddedDB(t *testing.T) {
	m, err := NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	// Apache 2.4.49 is the famous path-traversal pair.
	got := m.Match("apache", "2.4.49")
	if len(got) < 2 {
		t.Errorf("expected >=2 CVEs for apache 2.4.49, got %d", len(got))
	}
	// nginx 1.24.0 is patched — no CVEs.
	if hits := m.Match("nginx", "1.24.0"); len(hits) != 0 {
		t.Errorf("nginx 1.24.0 should be clean, got %v", hits)
	}
	// Case-insensitive product lookup.
	if hits := m.Match("NGINX", "1.20.0"); len(hits) == 0 {
		t.Error("expected CVE for nginx 1.20.0 (case-insensitive)")
	}
}

func TestEnrichRaisesSeverityAndAddsCVE(t *testing.T) {
	m, err := NewMatcher()
	if err != nil {
		t.Fatal(err)
	}
	f := asset.Finding{
		Type:     asset.FindingVersionDisclosure,
		Severity: asset.SeverityLow,
		Product:  "apache",
		Version:  "2.4.49",
	}
	out := m.Enrich(f)
	if len(out.CVE) == 0 {
		t.Fatal("expected CVEs attached")
	}
	if out.CVSS < 9.0 {
		t.Errorf("expected critical CVSS, got %.1f", out.CVSS)
	}
	if out.Severity != asset.SeverityCritical {
		t.Errorf("severity should be raised to critical, got %s", out.Severity)
	}
	if out.Source != asset.SourceCVE {
		t.Errorf("source = %s, want cve", out.Source)
	}
}

func TestEnrichNoMatchUnchanged(t *testing.T) {
	m, _ := NewMatcher()
	f := asset.Finding{Type: asset.FindingVersionDisclosure, Severity: asset.SeverityLow, Product: "nginx", Version: "1.24.0"}
	out := m.Enrich(f)
	if len(out.CVE) != 0 || out.Severity != asset.SeverityLow {
		t.Errorf("clean version should be unchanged, got %+v", out)
	}
}
