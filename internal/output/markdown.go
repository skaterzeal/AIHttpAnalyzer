package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

var severityOrder = []asset.Severity{
	asset.SeverityCritical, asset.SeverityHigh, asset.SeverityMedium,
	asset.SeverityLow, asset.SeverityInfo,
}

// WriteMarkdown renders a human-readable report: a severity summary table,
// followed by findings grouped by severity (highest first).
func WriteMarkdown(w io.Writer, results []asset.AnalyzedResponse, min asset.Severity) error {
	findings := Findings(results, min)

	counts := map[asset.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	endpoints := map[string]struct{}{}
	techs := map[string]struct{}{}
	for _, ar := range results {
		for _, e := range ar.Endpoints {
			endpoints[e] = struct{}{}
		}
		for _, t := range ar.Technologies {
			techs[t] = struct{}{}
		}
	}

	var b strings.Builder
	b.WriteString("# HTTP Analyzer Report\n\n")
	b.WriteString(fmt.Sprintf("- Responses analyzed: **%d**\n", len(results)))
	b.WriteString(fmt.Sprintf("- Findings: **%d**\n", len(findings)))
	b.WriteString(fmt.Sprintf("- Unique endpoints: **%d**\n", len(endpoints)))
	b.WriteString(fmt.Sprintf("- Technologies: **%s**\n\n", joinSorted(techs)))

	b.WriteString("## Severity Summary\n\n| Severity | Count |\n|---|---|\n")
	for _, s := range severityOrder {
		b.WriteString(fmt.Sprintf("| %s | %d |\n", strings.ToUpper(string(s)), counts[s]))
	}
	b.WriteString("\n")

	for _, s := range severityOrder {
		group := filterBySeverity(findings, s)
		if len(group) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("## %s (%d)\n\n", strings.ToUpper(string(s)), len(group)))
		for _, f := range group {
			b.WriteString(fmt.Sprintf("### %s\n", f.Title))
			b.WriteString(fmt.Sprintf("- Asset: `%s`\n", f.Asset))
			b.WriteString(fmt.Sprintf("- Type: `%s` | Confidence: %.2f | Source: %s\n", f.Type, f.Confidence, f.Source))
			if len(f.CVE) > 0 {
				b.WriteString(fmt.Sprintf("- CVE: %s (CVSS %.1f)\n", strings.Join(f.CVE, ", "), f.CVSS))
			}
			if f.Detail != "" {
				b.WriteString(fmt.Sprintf("- Detail: %s\n", oneLine(f.Detail)))
			}
			if f.Evidence != "" {
				b.WriteString(fmt.Sprintf("- Evidence: `%s`\n", oneLine(f.Evidence)))
			}
			b.WriteString("\n")
		}
	}

	writeAITriage(&b, results)

	_, err := io.WriteString(w, b.String())
	return err
}

// writeAITriage appends advisory AI sections, clearly labeled as non-authoritative.
func writeAITriage(b *strings.Builder, results []asset.AnalyzedResponse) {
	var any bool
	for _, ar := range results {
		if ar.AITriage != nil {
			any = true
			break
		}
	}
	if !any {
		return
	}
	b.WriteString("## AI Triage (advisory)\n\n")
	for _, ar := range results {
		tr := ar.AITriage
		if tr == nil {
			continue
		}
		fmt.Fprintf(b, "### `%s` — %s\n", assetID(ar), tr.Provider)
		if tr.Summary != "" {
			fmt.Fprintf(b, "%s\n\n", oneLine(tr.Summary))
		}
		if len(tr.InjectionDetected) > 0 {
			fmt.Fprintf(b, "- ⚠️ Prompt injection detected in body: %s\n", strings.Join(tr.InjectionDetected, "; "))
		}
		for _, tst := range tr.RecommendedTests {
			fmt.Fprintf(b, "- Test: %s\n", oneLine(tst))
		}
		for _, ep := range tr.UnverifiedEndpoints {
			fmt.Fprintf(b, "- Unverified endpoint (AI guess): `%s`\n", ep)
		}
		b.WriteString("\n")
	}
}

func filterBySeverity(fs []asset.Finding, s asset.Severity) []asset.Finding {
	var out []asset.Finding
	for _, f := range fs {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

func joinSorted(set map[string]struct{}) string {
	if len(set) == 0 {
		return "—"
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func oneLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
}
