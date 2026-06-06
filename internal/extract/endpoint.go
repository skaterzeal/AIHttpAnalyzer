package extract

import (
	"regexp"
	"sort"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// endpointPatterns extract API paths and URLs referenced inside a response body.
var endpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`"(?:url|endpoint|href|action|src|link|path|api_url|base_url)"\s*:\s*"(/[^"]{2,})"`),
	regexp.MustCompile(`action=["']([^"']+)["']`),
	regexp.MustCompile(`href=["'](/[a-zA-Z0-9/_\-?.=&%#]+)["']`),
	regexp.MustCompile(`(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](/[^'"]+)`),
	regexp.MustCompile(`"(/(?:api|v\d+|rest|graphql|gql|rpc)/[a-zA-Z0-9/_\-?.=&%#]+)"`),
	regexp.MustCompile(`"(/[a-zA-Z][a-zA-Z0-9/_\-]{3,}(?:\.[a-zA-Z]{2,4})?)"`),
}

var endpointBlocklist = map[string]struct{}{
	"/": {}, "//": {}, "/.": {}, "/*": {}, "/null": {}, "/undefined": {},
	"/true": {}, "/false": {}, "/0": {}, "/1": {},
}

// reInvalidPathChar rejects paths containing characters that should never appear
// in a real URL path, keeping the endpoint list low-noise.
var reInvalidPathChar = regexp.MustCompile(`[<>{}|\\^` + "`" + `\[\]\s]`)

// fsPathPrefixes are leading segments that mark an OS filesystem path rather than
// an HTTP endpoint. These leak into bodies via stack traces and env dumps (e.g.
// "/usr/local/bin", "/home/app/views.py") and are a major source of endpoint
// false positives.
var fsPathPrefixes = []string{
	"/usr/", "/opt/", "/etc/", "/var/", "/home/", "/tmp/", "/bin/",
	"/sbin/", "/lib/", "/lib64/", "/proc/", "/dev/", "/root/", "/mnt/",
	"/boot/", "/run/",
}

// srcFileExts are source-file extensions that indicate a code path from a stack
// trace, not a routable endpoint.
var srcFileExts = []string{
	".py", ".java", ".rb", ".php", ".go", ".rs", ".c", ".cpp", ".cs",
	".class", ".jar", ".pyc",
}

// EndpointExtractor discovers endpoints referenced in bodies and Location
// headers. It returns plain paths (not findings) for the attack-surface map.
type EndpointExtractor struct{}

// NewEndpointExtractor constructs the extractor.
func NewEndpointExtractor() *EndpointExtractor { return &EndpointExtractor{} }

// Extract returns a sorted, de-duplicated list of discovered endpoint paths.
func (e *EndpointExtractor) Extract(r *asset.HTTPResponse) []string {
	found := make(map[string]struct{})
	for _, re := range endpointPatterns {
		for _, m := range re.FindAllStringSubmatch(r.Body, -1) {
			if len(m) < 2 {
				continue
			}
			p := m[1]
			if isValidPath(p) {
				found[p] = struct{}{}
			}
		}
	}
	for _, h := range []string{"location", "content-location"} {
		if v := r.Headers[h]; len(v) > 0 && v[0] == '/' {
			if isValidPath(v) {
				found[v] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func isValidPath(p string) bool {
	if _, blocked := endpointBlocklist[p]; blocked {
		return false
	}
	if len(p) < 2 || len(p) > 200 {
		return false
	}
	if reInvalidPathChar.MatchString(p) {
		return false
	}
	if looksLikeFilesystemPath(p) {
		return false
	}
	return true
}

// looksLikeFilesystemPath reports whether p is an OS path or source file
// reference rather than an HTTP endpoint.
func looksLikeFilesystemPath(p string) bool {
	for _, pre := range fsPathPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	lower := strings.ToLower(p)
	for _, ext := range srcFileExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
