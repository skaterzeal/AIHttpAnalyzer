package ai

import (
	"regexp"
	"strings"
)

// injectionPatterns detect text in a response body that tries to hijack the
// LLM. We do not try to "clean" the body — that is a losing game — we DETECT and
// WARN, and structurally fence the body as data (see WrapUntrusted). Detection
// is surfaced to the operator so they know the target tried to manipulate the
// analysis.
var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (?:all |the )?(?:previous|prior|above|earlier) (?:instructions|prompts?|context)`),
	regexp.MustCompile(`(?i)disregard (?:all |the )?(?:previous|prior|above) `),
	regexp.MustCompile(`(?i)you are now (?:a|an|the) `),
	regexp.MustCompile(`(?i)\bsystem prompt\b`),
	regexp.MustCompile(`(?i)\bact as\b.{0,40}\b(?:assistant|model|ai)\b`),
	regexp.MustCompile(`(?i)</?(?:system|assistant|user)>`),
	regexp.MustCompile(`(?i)new instructions?:`),
	regexp.MustCompile(`(?i)reveal (?:your |the )?(?:system )?(?:prompt|instructions)`),
}

// DetectInjection returns the injection phrases found in the body (deduplicated).
func DetectInjection(body string) []string {
	seen := map[string]struct{}{}
	var hits []string
	for _, re := range injectionPatterns {
		for _, m := range re.FindAllString(body, -1) {
			m = strings.TrimSpace(m)
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			hits = append(hits, m)
		}
	}
	return hits
}

// untrustedFence is a randomized-looking, unlikely-to-collide delimiter that
// fences attacker-controlled content. The model is told everything between the
// markers is data, never instructions.
const (
	fenceOpen  = "<<<UNTRUSTED_DATA_8f3a2c id=%s>>>"
	fenceClose = "<<<END_UNTRUSTED_DATA_8f3a2c id=%s>>>"
)

// WrapUntrusted fences content so the model treats it as inert data. The id ties
// the open/close markers together and is hard for injected text to forge.
func WrapUntrusted(id, content string) string {
	var b strings.Builder
	b.WriteString(strings.Replace(fenceOpen, "%s", id, 1))
	b.WriteByte('\n')
	b.WriteString(content)
	b.WriteByte('\n')
	b.WriteString(strings.Replace(fenceClose, "%s", id, 1))
	return b.String()
}

// sensitiveHeaders are redacted before any request context is sent to a hosted
// LLM, so credentials never leave the operator's machine via the AI call.
var sensitiveHeaders = map[string]struct{}{
	"authorization": {}, "cookie": {}, "set-cookie": {},
	"x-api-key": {}, "x-auth-token": {}, "xsrf-token": {},
	"csrf-token": {}, "x-csrf-token": {}, "proxy-authorization": {},
}

// RedactHeaders returns a copy of headers with sensitive values masked.
func RedactHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if _, ok := sensitiveHeaders[strings.ToLower(k)]; ok {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}
