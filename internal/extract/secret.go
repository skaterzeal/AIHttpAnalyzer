package extract

import (
	"regexp"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

// secretPatterns target secrets that leak in HTTP *responses* specifically
// (JSON key/value pairs, tokens, keys, internal infra references).
var secretPatterns = []secretPattern{
	{"api_key_json", regexp.MustCompile(`"(?:api_?key|apikey|access_?key)"\s*:\s*"([^"]{12,})"`)},
	{"token_json", regexp.MustCompile(`"(?:token|access_token|auth_token)"\s*:\s*"([^"]{12,})"`)},
	{"password_json", regexp.MustCompile(`"(?:password|passwd|pwd|secret)"\s*:\s*"([^"]{6,})"`)},
	{"aws_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"github_token", regexp.MustCompile(`gh[oprsu]_[A-Za-z0-9]{36}`)},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,48}`)},
	{"slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}`)},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"stripe_secret", regexp.MustCompile(`[sr]k_live_[0-9a-zA-Z]{24,}`)},
	{"sendgrid_key", regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`)},
	{"npm_token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
	{"db_url", regexp.MustCompile(`(?:mysql|postgresql|mongodb|redis)://[^\s'"<>]+`)},
	{"internal_ip", regexp.MustCompile(`(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+`)},
	{"email_internal", regexp.MustCompile(`[a-zA-Z0-9._%+-]+@(?:internal|corp|local|intranet)\.[a-zA-Z]+`)},
}

// secretBlocklist filters obvious placeholder values that match a pattern but
// are not real secrets.
var secretBlocklist = map[string]struct{}{
	"null": {}, "false": {}, "true": {}, "none": {}, "undefined": {},
	"password": {}, "secret": {}, "admin": {}, "default": {}, "changeit": {},
	"qwerty": {}, "test": {}, "testing": {}, "welcome": {}, "123456": {},
	"12345678": {}, "123456789": {}, "12345": {}, "password123": {}, "secret123": {},
}

// SecretExtractor finds exposed secrets in response bodies, using entropy and a
// blocklist to keep false positives low.
type SecretExtractor struct{}

// NewSecretExtractor constructs the extractor (patterns are package-level).
func NewSecretExtractor() *SecretExtractor { return &SecretExtractor{} }

// Extract returns one finding per high-confidence secret match. Evidence is
// redacted (first/last 4 chars) so the tool never echoes a full live secret.
func (e *SecretExtractor) Extract(r *asset.HTTPResponse) []asset.Finding {
	var findings []asset.Finding
	body := r.Body
	for _, sp := range secretPatterns {
		for _, m := range sp.re.FindAllStringSubmatchIndex(body, -1) {
			value := matchValue(body, m)
			lower := strings.ToLower(strings.TrimSpace(value))
			if _, blocked := secretBlocklist[lower]; blocked {
				continue
			}
			if len(value) < 6 {
				continue
			}
			entropy := shannonEntropy(value)
			if !secretQualityOK(sp.name, value, entropy) {
				continue
			}
			findings = append(findings, asset.Finding{
				Asset:      r.AssetID(),
				Type:       asset.FindingSecretExposure,
				Severity:   asset.SeverityHigh,
				Title:      "Secret in response: " + sp.name,
				Detail:     "Pattern " + sp.name + " matched in body",
				Evidence:   redact(value),
				Location:   "body",
				Confidence: 0.8,
				Source:     asset.SourceDeterministic,
			})
		}
	}
	return findings
}

// matchValue returns capture group 1 if present, else the whole match.
func matchValue(body string, idx []int) string {
	if len(idx) >= 4 && idx[2] >= 0 {
		return body[idx[2]:idx[3]]
	}
	return body[idx[0]:idx[1]]
}

// secretQualityOK applies per-type entropy/length gates to reduce noise.
func secretQualityOK(name, value string, entropy float64) bool {
	switch name {
	case "api_key_json", "token_json", "jwt":
		if len(value) < 12 || entropy < 2.5 {
			return false
		}
	case "password_json":
		if len(uniqueRunes(value)) <= 2 || entropy < 1.8 {
			return false
		}
	}
	return true
}

func uniqueRunes(s string) map[rune]struct{} {
	set := make(map[rune]struct{})
	for _, c := range s {
		set[c] = struct{}{}
	}
	return set
}

// redact masks the middle of a secret, keeping only enough to recognize it.
func redact(v string) string {
	if len(v) > 8 {
		return v[:4] + "***" + v[len(v)-4:]
	}
	return v
}
