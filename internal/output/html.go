package output

import (
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// htmlData is the view model for the report template.
type htmlData struct {
	GeneratedAt  string
	Total        int
	FindingCount int
	Counts       map[string]int
	Findings     []asset.Finding
	Technologies []string
	Endpoints    []string
	CVEs         []string
	AITriages    []htmlTriage
}

type htmlTriage struct {
	Asset  string
	Triage *asset.AITriage
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": func(s asset.Severity) string { return string(s) },
}).Parse(reportHTML))

// WriteHTML renders a self-contained, styled HTML report.
func WriteHTML(w io.Writer, results []asset.AnalyzedResponse, min asset.Severity) error {
	findings := Findings(results, min)
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Severity.Rank() > findings[j].Severity.Rank()
	})

	counts := map[string]int{}
	for _, f := range findings {
		counts[string(f.Severity)]++
	}

	endpoints := map[string]struct{}{}
	techs := map[string]struct{}{}
	cves := map[string]struct{}{}
	var triages []htmlTriage
	for _, ar := range results {
		for _, e := range ar.Endpoints {
			endpoints[e] = struct{}{}
		}
		for _, t := range ar.Technologies {
			techs[t] = struct{}{}
		}
		for _, f := range ar.Findings {
			for _, c := range f.CVE {
				cves[c] = struct{}{}
			}
		}
		if ar.AITriage != nil {
			triages = append(triages, htmlTriage{Asset: assetID(ar), Triage: ar.AITriage})
		}
	}

	data := htmlData{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Total:        len(results),
		FindingCount: len(findings),
		Counts:       counts,
		Findings:     findings,
		Technologies: keysSorted(techs),
		Endpoints:    keysSorted(endpoints),
		CVEs:         keysSorted(cves),
		AITriages:    triages,
	}
	return htmlTmpl.Execute(w, data)
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const reportHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>httpanalyzer report</title>
<style>
:root{--bg:#0f1419;--card:#1a212b;--fg:#e6edf3;--muted:#8b949e;--line:#30363d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{font-size:22px;margin:0 0 4px}
.muted{color:var(--muted);font-size:13px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:96px}
.stat b{display:block;font-size:22px}
.sev{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700;text-transform:uppercase}
.critical{background:#7d1a1a;color:#ffd7d7}.high{background:#8a4b00;color:#ffe0bf}
.medium{background:#7a6500;color:#fff3bf}.low{background:#1f5130;color:#c8f3d4}.info{background:#30363d;color:#c9d1d9}
h2{font-size:16px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.f{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:8px;padding:12px 14px;margin:10px 0}
.f.critical{border-left-color:#e5534b}.f.high{border-left-color:#db8b2a}.f.medium{border-left-color:#d4c20a}.f.low{border-left-color:#3fb950}.f.info{border-left-color:#6e7681}
.f h3{margin:0 0 6px;font-size:15px}
.kv{color:var(--muted);font-size:13px;margin:2px 0}
code{background:#0d1117;border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:12px;word-break:break-all}
.tags span{display:inline-block;background:#0d1117;border:1px solid var(--line);border-radius:5px;padding:2px 7px;margin:2px;font-size:12px}
.cve{color:#ff9a9a;font-weight:600}
.ai{background:#11202b;border:1px solid #1f3a4d;border-radius:8px;padding:12px 14px;margin:10px 0}
</style></head><body><div class="wrap">
<h1>httpanalyzer report</h1>
<div class="muted">Generated {{.GeneratedAt}} · {{.Total}} responses · {{.FindingCount}} findings</div>

<div class="cards">
  <div class="stat"><b>{{index .Counts "critical"}}</b><span class="sev critical">critical</span></div>
  <div class="stat"><b>{{index .Counts "high"}}</b><span class="sev high">high</span></div>
  <div class="stat"><b>{{index .Counts "medium"}}</b><span class="sev medium">medium</span></div>
  <div class="stat"><b>{{index .Counts "low"}}</b><span class="sev low">low</span></div>
  <div class="stat"><b>{{index .Counts "info"}}</b><span class="sev info">info</span></div>
</div>

{{if .CVEs}}<h2>Correlated CVEs</h2><div class="tags">{{range .CVEs}}<span class="cve">{{.}}</span>{{end}}</div>{{end}}

<h2>Findings</h2>
{{range .Findings}}
<div class="f {{upper .Severity}}">
  <h3><span class="sev {{upper .Severity}}">{{upper .Severity}}</span> {{.Title}}</h3>
  <div class="kv">Asset: <code>{{.Asset}}</code></div>
  <div class="kv">Type: {{.Type}} · Confidence: {{printf "%.2f" .Confidence}} · Source: {{.Source}}</div>
  {{if .CVE}}<div class="kv">CVE: <span class="cve">{{range .CVE}}{{.}} {{end}}</span>(CVSS {{printf "%.1f" .CVSS}})</div>{{end}}
  {{if .Detail}}<div class="kv">{{.Detail}}</div>{{end}}
  {{if .Evidence}}<div class="kv">Evidence: <code>{{.Evidence}}</code></div>{{end}}
</div>
{{else}}<p class="muted">No findings at this severity threshold.</p>{{end}}

{{if .Technologies}}<h2>Technologies</h2><div class="tags">{{range .Technologies}}<span>{{.}}</span>{{end}}</div>{{end}}

{{if .Endpoints}}<h2>Endpoints ({{len .Endpoints}})</h2><div class="tags">{{range .Endpoints}}<span>{{.}}</span>{{end}}</div>{{end}}

{{if .AITriages}}<h2>AI Triage <span class="muted">(advisory — not authoritative)</span></h2>
{{range .AITriages}}<div class="ai">
  <div class="kv"><code>{{.Asset}}</code> — {{.Triage.Provider}}</div>
  {{if .Triage.Summary}}<p>{{.Triage.Summary}}</p>{{end}}
  {{if .Triage.InjectionDetected}}<div class="kv">⚠️ Prompt injection detected in body</div>{{end}}
  {{if .Triage.RecommendedTests}}<ul>{{range .Triage.RecommendedTests}}<li>{{.}}</li>{{end}}</ul>{{end}}
</div>{{end}}{{end}}

</div></body></html>`
