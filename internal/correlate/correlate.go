// Package correlate aggregates per-response analysis into a cross-asset view:
// it deduplicates findings and builds the attack-surface map. This is where the
// "143 responses, the same 'missing CSP' 100 times" noise problem is solved.
package correlate

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func nowUTC() time.Time { return time.Now().UTC() }

// DedupeFindings collapses findings that are effectively identical. Two findings
// are duplicates when they share asset, type, title, and evidence — i.e. the
// same issue seen again. First occurrence wins; order is preserved.
func DedupeFindings(in []asset.Finding) []asset.Finding {
	seen := make(map[string]struct{}, len(in))
	out := make([]asset.Finding, 0, len(in))
	for _, f := range in {
		key := f.Asset + "\x00" + string(f.Type) + "\x00" + f.Title + "\x00" + f.Evidence
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

// BuildMap aggregates analyzed responses into an attack-surface map. Findings of
// critical/high severity are collected (deduplicated) as the priority list.
func BuildMap(results []asset.AnalyzedResponse) asset.AttackSurfaceMap {
	endpoints := newStringSet()
	techs := newStringSet()
	cves := newStringSet()
	var critical []asset.Finding

	for _, ar := range results {
		endpoints.addAll(ar.Endpoints)
		techs.addAll(ar.Technologies)
		for _, f := range ar.Findings {
			cves.addAll(f.CVE)
			if f.Severity == asset.SeverityCritical || f.Severity == asset.SeverityHigh {
				critical = append(critical, f)
			}
		}
	}
	critical = DedupeFindings(critical)
	sort.SliceStable(critical, func(i, j int) bool {
		return critical[i].Severity.Rank() > critical[j].Severity.Rank()
	})

	m := asset.AttackSurfaceMap{
		Target:           deriveTarget(results),
		TotalResponses:   len(results),
		UniqueEndpoints:  endpoints.sorted(),
		Technologies:     techs.sorted(),
		CVEs:             cves.sorted(),
		CriticalFindings: critical,
		GeneratedAt:      nowUTC(),
	}
	m.Summary = fmt.Sprintf(
		"%d responses analyzed. %d unique endpoints, %d technologies, %d CVEs, %d high/critical findings.",
		m.TotalResponses, len(m.UniqueEndpoints), len(m.Technologies), len(m.CVEs), len(m.CriticalFindings),
	)
	return m
}

// deriveTarget guesses the engagement target from the first response's host.
func deriveTarget(results []asset.AnalyzedResponse) string {
	for _, ar := range results {
		if ar.Response == nil || ar.Response.Request == nil {
			continue
		}
		if u, err := url.Parse(ar.Response.Request.URL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return ""
}

// --- small ordered-set helper ---

type stringSet struct{ m map[string]struct{} }

func newStringSet() *stringSet { return &stringSet{m: map[string]struct{}{}} }

func (s *stringSet) addAll(vs []string) {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			s.m[v] = struct{}{}
		}
	}
}

func (s *stringSet) sorted() []string {
	out := make([]string, 0, len(s.m))
	for v := range s.m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
