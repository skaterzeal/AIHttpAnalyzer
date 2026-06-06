package extract

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// deriveProduct extracts the product name from a full version match like
// "nginx/1.24.0" by stripping the version and trailing separators. Returns ""
// when the match is version-only (e.g. a bare X-AspNet-Version header).
func deriveProduct(full, version string) string {
	i := strings.LastIndex(full, version)
	if i <= 0 {
		return ""
	}
	p := strings.TrimRight(full[:i], "/ \t-@")
	return strings.ToLower(p)
}

type compiledVersion struct {
	pat versionPattern
	re  *regexp.Regexp
}

// VersionExtractor detects framework/server/library version disclosures in
// headers and bodies. Detected product+version pairs are later fed to CVE
// correlation (Faz 2).
type VersionExtractor struct {
	patterns []compiledVersion
}

// NewVersionExtractor compiles the embedded version patterns (case-insensitive,
// mirroring the reference implementation).
func NewVersionExtractor(l Loader) (*VersionExtractor, error) {
	var f versionPatternFile
	if err := l.load("version_patterns.yaml", &f); err != nil {
		return nil, err
	}
	e := &VersionExtractor{}
	for _, p := range f.Patterns {
		re, err := regexp.Compile("(?i)" + p.Regex)
		if err != nil {
			return nil, fmt.Errorf("version pattern %s: %w", p.ID, err)
		}
		e.patterns = append(e.patterns, compiledVersion{pat: p, re: re})
	}
	return e, nil
}

// Extract returns one finding per matched version pattern. The captured version
// (group 1 when present) is reported in the detail and as Title for CVE lookup.
func (e *VersionExtractor) Extract(r *asset.HTTPResponse) []asset.Finding {
	var findings []asset.Finding
	for _, cp := range e.patterns {
		var target string
		switch cp.pat.Source {
		case "header":
			target = r.Headers[cp.pat.HeaderName]
		case "body":
			target = r.Body
		}
		if target == "" {
			continue
		}
		m := cp.re.FindStringSubmatch(target)
		if m == nil {
			continue
		}
		version := m[0]
		if len(m) > 1 && m[1] != "" {
			version = m[1]
		}
		product := cp.pat.Product
		if product == "" {
			product = deriveProduct(m[0], version)
		}
		loc := "body"
		if cp.pat.Source == "header" {
			loc = "header:" + cp.pat.HeaderName
		}
		title := cp.pat.Name
		if product != "" {
			title = product + " " + version
		}
		findings = append(findings, asset.Finding{
			Asset:      r.AssetID(),
			Type:       asset.FindingVersionDisclosure,
			Severity:   asset.ParseSeverity(cp.pat.Severity),
			Title:      title,
			Detail:     "Detected version: " + version,
			Evidence:   truncate(m[0], 120),
			Location:   loc,
			Product:    product,
			Version:    version,
			Confidence: 0.9,
			Source:     asset.SourceDeterministic,
		})
	}
	return findings
}
