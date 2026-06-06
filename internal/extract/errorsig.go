package extract

import (
	"regexp"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// errPattern is a single signature pattern, pre-compiled when it is valid regex.
// Some signatures (e.g. "SwaggerUIBundle(") are not valid regex; for those we
// fall back to a case-insensitive substring match, mirroring the reference
// implementation's behavior.
type errPattern struct {
	raw string
	re  *regexp.Regexp // nil => use literal substring match
}

type compiledErrorSig struct {
	sig      errorSignature
	patterns []errPattern
}

// ErrorExtractor detects database/application error signatures and dangerous
// disclosures (SQL errors, debug mode, exposed actuators, AWS metadata, ...).
type ErrorExtractor struct {
	sigs []compiledErrorSig
}

// NewErrorExtractor compiles the embedded error signatures.
func NewErrorExtractor(l Loader) (*ErrorExtractor, error) {
	var f errorSignatureFile
	if err := l.load("error_signatures.yaml", &f); err != nil {
		return nil, err
	}
	e := &ErrorExtractor{}
	for _, s := range f.Sigs() {
		ce := compiledErrorSig{sig: s}
		for _, p := range s.Patterns {
			re, err := regexp.Compile("(?i)" + p)
			if err != nil {
				ce.patterns = append(ce.patterns, errPattern{raw: p})
				continue
			}
			ce.patterns = append(ce.patterns, errPattern{raw: p, re: re})
		}
		e.sigs = append(e.sigs, ce)
	}
	return e, nil
}

// Sigs is a tiny accessor so the loader reads naturally.
func (f errorSignatureFile) Sigs() []errorSignature { return f.Signatures }

// Extract returns at most one finding per signature (first matching pattern).
func (e *ErrorExtractor) Extract(r *asset.HTTPResponse) []asset.Finding {
	var findings []asset.Finding
	body := r.Body
	lowerBody := strings.ToLower(body)
	for _, ce := range e.sigs {
		matched := ""
		for _, p := range ce.patterns {
			if p.re != nil {
				if p.re.MatchString(body) {
					matched = p.raw
					break
				}
			} else if strings.Contains(lowerBody, strings.ToLower(p.raw)) {
				matched = p.raw
				break
			}
		}
		if matched == "" {
			continue
		}
		findings = append(findings, asset.Finding{
			Asset:      r.AssetID(),
			Type:       asset.FindingErrorMessage,
			Severity:   asset.ParseSeverity(ce.sig.Severity),
			Title:      ce.sig.Name,
			Detail:     ce.sig.Implication,
			Evidence:   matched,
			Location:   "body",
			Confidence: 0.85,
			Source:     asset.SourceDeterministic,
		})
	}
	return findings
}
