package asset

import (
	"encoding/json"
	"testing"
)

func TestSeverityRankOrdering(t *testing.T) {
	order := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Fatalf("%s should rank below %s", order[i-1], order[i])
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityHigh.AtLeast(SeverityMedium) {
		t.Error("high should be >= medium")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Error("low should not be >= high")
	}
	if !SeverityMedium.AtLeast(SeverityMedium) {
		t.Error("medium should be >= medium")
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical": SeverityCritical,
		"  HIGH  ": SeverityHigh,
		"Medium":   SeverityMedium,
		"bogus":    SeverityInfo,
		"":         SeverityInfo,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSeverityValid(t *testing.T) {
	if SeverityCritical.Valid() != true {
		t.Error("critical should be valid")
	}
	if Severity("nope").Valid() != false {
		t.Error("nope should be invalid")
	}
}

func TestAssetID(t *testing.T) {
	withURL := &HTTPResponse{Source: "burp", Request: &HTTPRequest{URL: "https://x/y"}}
	if got := withURL.AssetID(); got != "https://x/y" {
		t.Errorf("AssetID = %q, want url", got)
	}
	noURL := &HTTPResponse{Source: "file"}
	if got := noURL.AssetID(); got != "file" {
		t.Errorf("AssetID = %q, want source fallback", got)
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	f := Finding{
		Asset:      "https://api.example.com/v1/users",
		Type:       FindingVersionDisclosure,
		Severity:   SeverityHigh,
		Title:      "nginx 1.18.0",
		CVE:        []string{"CVE-2021-23017"},
		CVSS:       7.7,
		Confidence: 0.9,
		Source:     SourceDeterministic,
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var got Finding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Severity != SeverityHigh || got.CVSS != 7.7 || len(got.CVE) != 1 {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestAssetJSONOmitsEmpty(t *testing.T) {
	b, _ := json.Marshal(Asset{URL: "https://x"})
	// Empty fields should be omitted to keep JSONL lines compact.
	if got := string(b); got != `{"url":"https://x"}` {
		t.Errorf("unexpected JSON: %s", got)
	}
}
