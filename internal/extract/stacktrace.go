package extract

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

var (
	reFilePaths  = regexp.MustCompile(`(?:/[a-zA-Z0-9_\-./]+\.(?:py|php|java|rb|js|ts|cs))`)
	reLineNumber = regexp.MustCompile(`line (\d+)`)
	reExcType    = regexp.MustCompile(`[A-Za-z]+(?:Error|Exception|Warning)`)
)

type compiledStack struct {
	pat stackPattern
	re  *regexp.Regexp
}

// StackTraceExtractor finds language/framework stack traces in response bodies.
type StackTraceExtractor struct {
	patterns []compiledStack
}

// NewStackTraceExtractor compiles the embedded stack-trace patterns. Patterns
// are matched with dotall semantics to mirror the reference implementation, so a
// trace spanning multiple lines is captured whole.
func NewStackTraceExtractor(l Loader) (*StackTraceExtractor, error) {
	var f stackPatternFile
	if err := l.load("stack_traces.yaml", &f); err != nil {
		return nil, err
	}
	e := &StackTraceExtractor{}
	for _, p := range f.Patterns {
		re, err := regexp.Compile("(?s)" + p.Regex)
		if err != nil {
			return nil, fmt.Errorf("stacktrace pattern %s: %w", p.ID, err)
		}
		e.patterns = append(e.patterns, compiledStack{pat: p, re: re})
	}
	return e, nil
}

// Extract returns one finding per matched stack-trace pattern.
func (e *StackTraceExtractor) Extract(r *asset.HTTPResponse) []asset.Finding {
	var findings []asset.Finding
	body := r.Body
	for _, cp := range e.patterns {
		loc := cp.re.FindStringIndex(body)
		if loc == nil {
			continue
		}
		raw := body[loc[0]:loc[1]]
		detail := fmt.Sprintf("Framework: %s", strings.Join(cp.pat.Frameworks, ", "))
		if fields := extractStackFields(raw, cp.pat.ExtractFields); fields != "" {
			detail += "\n" + fields
		}
		findings = append(findings, asset.Finding{
			Asset:      r.AssetID(),
			Type:       asset.FindingStackTrace,
			Severity:   asset.ParseSeverity(cp.pat.Severity),
			Title:      cp.pat.Name,
			Detail:     detail,
			Evidence:   truncate(raw, 500),
			Location:   "body",
			Confidence: 0.95,
			Source:     asset.SourceDeterministic,
		})
	}
	return findings
}

func extractStackFields(trace string, fields []string) string {
	var parts []string
	for _, f := range fields {
		switch f {
		case "file_paths", "file_path":
			if m := reFilePaths.FindAllString(trace, -1); len(m) > 0 {
				parts = append(parts, "files="+strings.Join(dedupe(m), ","))
			}
		case "line_numbers", "line_number":
			if m := reLineNumber.FindAllStringSubmatch(trace, -1); len(m) > 0 {
				var nums []string
				for _, g := range m {
					nums = append(nums, g[1])
				}
				parts = append(parts, "lines="+strings.Join(dedupe(nums), ","))
			}
		case "exception_type", "exception_class", "error_type":
			if m := reExcType.FindString(trace); m != "" {
				parts = append(parts, "exception="+m)
			}
		}
	}
	return strings.Join(parts, " ")
}
