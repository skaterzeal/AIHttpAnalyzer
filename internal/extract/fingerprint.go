package extract

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// Weights for fingerprint scoring. Header indicators are stronger evidence than
// a body keyword, so they count more — an improvement over the reference's flat
// per-indicator scoring.
const (
	headerIndicatorWeight = 2.0
	bodyIndicatorWeight   = 1.0
	fingerprintThreshold  = 0.4
)

type compiledHeaderInd struct {
	name  string
	value string         // exact (lowercased) match, if set
	re    *regexp.Regexp // pattern match, if set
}

type compiledFingerprint struct {
	name       string
	headers    []compiledHeaderInd
	body       []string
	totalScore float64
}

// TechnologyFingerprinter identifies the tech stack from headers and body.
type TechnologyFingerprinter struct {
	fps []compiledFingerprint
}

// NewTechnologyFingerprinter compiles the embedded fingerprints.
func NewTechnologyFingerprinter(l Loader) (*TechnologyFingerprinter, error) {
	var f fingerprintFile
	if err := l.load("technology_fingerprints.yaml", &f); err != nil {
		return nil, err
	}
	t := &TechnologyFingerprinter{}
	for _, fp := range f.Fingerprints {
		cf := compiledFingerprint{name: fp.Name}
		for _, h := range fp.Indicators.Headers {
			ci := compiledHeaderInd{name: strings.ToLower(h.Name)}
			if h.Value != "" {
				ci.value = strings.ToLower(h.Value)
			} else if h.Pattern != "" {
				re, err := regexp.Compile("(?i)" + h.Pattern)
				if err != nil {
					return nil, fmt.Errorf("fingerprint %s header pattern: %w", fp.Name, err)
				}
				ci.re = re
			}
			cf.headers = append(cf.headers, ci)
			cf.totalScore += headerIndicatorWeight
		}
		for _, b := range fp.Indicators.Body {
			cf.body = append(cf.body, strings.ToLower(b))
			cf.totalScore += bodyIndicatorWeight
		}
		t.fps = append(t.fps, cf)
	}
	return t, nil
}

// Detect returns the names of technologies whose weighted indicator score meets
// the detection threshold.
func (t *TechnologyFingerprinter) Detect(r *asset.HTTPResponse) []string {
	lowerBody := strings.ToLower(r.Body)
	var detected []string
	for _, fp := range t.fps {
		if fp.totalScore == 0 {
			continue
		}
		var score float64
		for _, h := range fp.headers {
			val := r.Headers[h.name]
			switch {
			case h.value != "" && strings.ToLower(val) == h.value:
				score += headerIndicatorWeight
			case h.re != nil && h.re.MatchString(val):
				score += headerIndicatorWeight
			}
		}
		for _, kw := range fp.body {
			if strings.Contains(lowerBody, kw) {
				score += bodyIndicatorWeight
			}
		}
		if score/fp.totalScore >= fingerprintThreshold {
			detected = append(detected, fp.name)
		}
	}
	sort.Strings(detected)
	return detected
}
