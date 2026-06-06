package extract

import (
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// SecurityHeaderExtractor flags missing or dangerous security headers. It is
// deliberately content-type aware to keep false positives low: framing/CSP
// checks only apply to HTML (they are meaningless for a JSON API), HSTS only to
// HTTPS responses. These are real but low-severity findings, so they never drown
// out the high-impact detections.
type SecurityHeaderExtractor struct{}

// NewSecurityHeaderExtractor constructs the extractor.
func NewSecurityHeaderExtractor() *SecurityHeaderExtractor { return &SecurityHeaderExtractor{} }

// Extract returns misconfiguration findings for the response.
func (e *SecurityHeaderExtractor) Extract(r *asset.HTTPResponse) []asset.Finding {
	// Only assess successful, content-bearing responses; error/redirect pages
	// and empty bodies produce noisy, low-value header findings.
	if r.StatusCode != 0 && (r.StatusCode < 200 || r.StatusCode >= 400) {
		return nil
	}

	var findings []asset.Finding
	add := func(sev asset.Severity, title, detail, evidence string) {
		findings = append(findings, asset.Finding{
			Asset:      r.AssetID(),
			Type:       asset.FindingMisconfig,
			Severity:   sev,
			Title:      title,
			Detail:     detail,
			Evidence:   evidence,
			Location:   "headers",
			Confidence: 0.9,
			Source:     asset.SourceDeterministic,
		})
	}

	isHTML := strings.Contains(strings.ToLower(r.ContentType), "text/html")
	has := func(name string) bool { _, ok := r.Headers[name]; return ok }

	// nosniff matters for any content type that a browser might render.
	if !has("x-content-type-options") {
		add(asset.SeverityInfo, "Missing X-Content-Type-Options",
			"No nosniff header — browser may MIME-sniff the response.", "")
	}

	if isHTML {
		if !has("content-security-policy") {
			add(asset.SeverityLow, "Missing Content-Security-Policy",
				"No CSP — increases XSS/injection blast radius on this HTML page.", "")
		}
		if !has("x-frame-options") && !hasFrameAncestors(r.Headers["content-security-policy"]) {
			add(asset.SeverityLow, "Missing X-Frame-Options",
				"HTML page can be framed — clickjacking risk.", "")
		}
	}

	// HSTS only makes sense over HTTPS.
	if isHTTPS(r) && !has("strict-transport-security") {
		add(asset.SeverityLow, "Missing Strict-Transport-Security",
			"No HSTS on an HTTPS response — downgrade/MITM risk.", "")
	}

	// Dangerous CORS: wildcard origin, or reflected origin with credentials.
	if acao := r.Headers["access-control-allow-origin"]; acao != "" {
		acac := strings.EqualFold(r.Headers["access-control-allow-credentials"], "true")
		switch {
		case acao == "*" && acac:
			add(asset.SeverityHigh, "Permissive CORS with credentials",
				"ACAO:* together with credentials is invalid-but-dangerous and may expose authenticated data.",
				"Access-Control-Allow-Origin: *")
		case acac && acao != "*":
			add(asset.SeverityMedium, "Reflective CORS with credentials",
				"Origin appears reflected with credentials allowed — test for cross-origin data theft.",
				"Access-Control-Allow-Origin: "+acao)
		case acao == "*":
			add(asset.SeverityLow, "Wildcard CORS",
				"ACAO:* exposes responses to any origin (no credentials).",
				"Access-Control-Allow-Origin: *")
		}
	}

	return findings
}

// hasFrameAncestors reports whether a CSP already constrains framing, in which
// case a missing X-Frame-Options is not a real gap.
func hasFrameAncestors(csp string) bool {
	return strings.Contains(strings.ToLower(csp), "frame-ancestors")
}

// isHTTPS reports whether the response was served over HTTPS, inferred from the
// request URL. Unknown scheme is treated as not-HTTPS to avoid false positives.
func isHTTPS(r *asset.HTTPResponse) bool {
	return r.Request != nil && strings.HasPrefix(strings.ToLower(r.Request.URL), "https://")
}
