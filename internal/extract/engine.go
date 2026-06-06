package extract

import (
	"time"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/cve"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// Engine runs all deterministic extractors over a response. Its output is
// treated as ground truth: severities here are authoritative and are never
// overridden by the AI layer.
type Engine struct {
	stack    *StackTraceExtractor
	version  *VersionExtractor
	errsig   *ErrorExtractor
	secret   *SecretExtractor
	endpoint *EndpointExtractor
	fp       *TechnologyFingerprinter
	sechdr   *SecurityHeaderExtractor
	cve      *cve.Matcher
}

// Config customizes the engine. Both fields are optional; empty means use the
// embedded packs. PatternsDir lets users override/extend detection patterns and
// CVEDBPath swaps in a larger/custom CVE database — without rebuilding.
type Config struct {
	PatternsDir string
	CVEDBPath   string
}

// NewEngine constructs the engine with the embedded pattern packs and CVE DB.
func NewEngine() (*Engine, error) { return NewEngineWithConfig(Config{}) }

// NewEngineWithConfig constructs the engine, compiling every pattern pack. It
// returns an error if any pattern fails to compile, so a broken pack is caught
// at startup rather than silently dropping detections.
func NewEngineWithConfig(cfg Config) (*Engine, error) {
	l := Loader{Dir: cfg.PatternsDir}
	stack, err := NewStackTraceExtractor(l)
	if err != nil {
		return nil, err
	}
	version, err := NewVersionExtractor(l)
	if err != nil {
		return nil, err
	}
	errsig, err := NewErrorExtractor(l)
	if err != nil {
		return nil, err
	}
	fp, err := NewTechnologyFingerprinter(l)
	if err != nil {
		return nil, err
	}
	matcher, err := newMatcher(cfg.CVEDBPath)
	if err != nil {
		return nil, err
	}
	return &Engine{
		stack:    stack,
		version:  version,
		errsig:   errsig,
		secret:   NewSecretExtractor(),
		endpoint: NewEndpointExtractor(),
		fp:       fp,
		sechdr:   NewSecurityHeaderExtractor(),
		cve:      matcher,
	}, nil
}

// newMatcher loads the CVE matcher from an external file when path is set,
// otherwise from the embedded database.
func newMatcher(path string) (*cve.Matcher, error) {
	if path != "" {
		return cve.NewMatcherFromFile(path)
	}
	return cve.NewMatcher()
}

// Analyze runs every extractor over r and returns the combined result.
func (e *Engine) Analyze(r *asset.HTTPResponse) asset.AnalyzedResponse {
	var findings []asset.Finding
	findings = append(findings, e.stack.Extract(r)...)
	for _, vf := range e.version.Extract(r) {
		// Correlate detected versions with known CVEs (offline). Severity is
		// raised deterministically from CVSS, never by the AI layer.
		findings = append(findings, e.cve.Enrich(vf))
	}
	findings = append(findings, e.secret.Extract(r)...)
	findings = append(findings, e.errsig.Extract(r)...)
	findings = append(findings, e.sechdr.Extract(r)...)

	return asset.AnalyzedResponse{
		Response:     r,
		Findings:     findings,
		Endpoints:    e.endpoint.Extract(r),
		Technologies: e.fp.Detect(r),
		AnalyzedAt:   time.Now().UTC(),
	}
}
