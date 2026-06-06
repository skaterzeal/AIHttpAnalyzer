// Package cve correlates detected product versions with known CVEs. It is
// offline-first: a curated, high-signal database is embedded in the binary so
// the killer feature works with zero setup and no network. The dataset is
// intentionally small and precise rather than a full NVD mirror — every entry
// is a well-known, version-bounded vulnerability for a product the tool
// fingerprints, which keeps false positives near zero.
package cve

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

//go:embed db.json
var dbBytes []byte

// Entry is one vulnerability record for a product/version range.
type Entry struct {
	CVE         string  `json:"cve"`
	CVSS        float64 `json:"cvss"`
	Affected    string  `json:"affected"`
	Description string  `json:"description"`
}

// Matcher resolves product+version pairs to CVEs.
type Matcher struct {
	db map[string][]Entry
}

// NewMatcher loads the embedded CVE database.
func NewMatcher() (*Matcher, error) { return NewMatcherFromBytes(dbBytes) }

// NewMatcherFromFile loads a CVE database from a JSON file on disk, letting
// users supply a larger or custom database without rebuilding the binary.
func NewMatcherFromFile(path string) (*Matcher, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cve db %s: %w", path, err)
	}
	return NewMatcherFromBytes(b)
}

// NewMatcherFromBytes loads a CVE database from JSON bytes (used in tests and
// for user-supplied databases).
func NewMatcherFromBytes(b []byte) (*Matcher, error) {
	var db map[string][]Entry
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, fmt.Errorf("parse cve db: %w", err)
	}
	// Normalize product keys to lowercase for case-insensitive lookup.
	norm := make(map[string][]Entry, len(db))
	for k, v := range db {
		norm[strings.ToLower(k)] = v
	}
	return &Matcher{db: norm}, nil
}

// Match returns every CVE entry whose version constraint the given version
// satisfies, for the given product.
func (m *Matcher) Match(product, version string) []Entry {
	if product == "" || version == "" {
		return nil
	}
	entries := m.db[strings.ToLower(product)]
	var out []Entry
	for _, e := range entries {
		if satisfies(version, e.Affected) {
			out = append(out, e)
		}
	}
	return out
}

// SeverityForCVSS maps a CVSS score to the tool's severity scale.
func SeverityForCVSS(score float64) asset.Severity {
	switch {
	case score >= 9.0:
		return asset.SeverityCritical
	case score >= 7.0:
		return asset.SeverityHigh
	case score >= 4.0:
		return asset.SeverityMedium
	default:
		return asset.SeverityLow
	}
}

// Enrich augments a version-disclosure finding with correlated CVEs. The
// finding's severity is raised to match the worst CVE (severity is still
// deterministic — derived from CVSS, never from an LLM). It returns the
// (possibly unchanged) finding.
func (m *Matcher) Enrich(f asset.Finding) asset.Finding {
	if f.Type != asset.FindingVersionDisclosure {
		return f
	}
	matches := m.Match(f.Product, f.Version)
	if len(matches) == 0 {
		return f
	}

	cveSet := map[string]struct{}{}
	var ids []string
	var maxCVSS float64
	var worst string
	for _, e := range matches {
		if _, ok := cveSet[e.CVE]; !ok {
			cveSet[e.CVE] = struct{}{}
			ids = append(ids, e.CVE)
		}
		if e.CVSS > maxCVSS {
			maxCVSS = e.CVSS
			worst = e.Description
		}
	}
	sort.Strings(ids)

	f.CVE = ids
	f.CVSS = maxCVSS
	if sev := SeverityForCVSS(maxCVSS); sev.AtLeast(f.Severity) {
		f.Severity = sev
	}
	f.Source = asset.SourceCVE
	if worst != "" {
		f.Detail = fmt.Sprintf("%s %s — %s (CVSS %.1f): %s",
			f.Product, f.Version, strings.Join(ids, ", "), maxCVSS, worst)
	}
	return f
}
