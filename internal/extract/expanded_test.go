package extract

import (
	"strings"
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// analyzeBody is a helper that runs the full engine over a synthetic response.
func analyzeBody(t *testing.T, headers map[string]string, body string) asset.AnalyzedResponse {
	t.Helper()
	if headers == nil {
		headers = map[string]string{}
	}
	e := newEngine(t)
	return e.Analyze(&asset.HTTPResponse{
		StatusCode: 200,
		Headers:    headers,
		Body:       body,
		Source:     "test",
		Request:    &asset.HTTPRequest{URL: "https://t/"},
	})
}

func findByProduct(fs []asset.Finding, product string) *asset.Finding {
	for i := range fs {
		if fs[i].Product == product {
			return &fs[i]
		}
	}
	return nil
}

func TestTomcatGhostcatCVE(t *testing.T) {
	ar := analyzeBody(t, nil, "<html>Powered by Apache Tomcat/9.0.30</html>")
	f := findByProduct(ar.Findings, "tomcat")
	if f == nil || len(f.CVE) == 0 || f.Severity != asset.SeverityCritical {
		t.Fatalf("expected Tomcat Ghostcat CVE (critical), got %+v", f)
	}
	if f.CVE[0] != "CVE-2020-1938" {
		t.Errorf("expected CVE-2020-1938, got %v", f.CVE)
	}
}

func TestDrupalgeddonCVE(t *testing.T) {
	ar := analyzeBody(t, nil, "<meta name=Generator content='Drupal 7.50'>")
	f := findByProduct(ar.Findings, "drupal")
	if f == nil || f.Severity != asset.SeverityCritical {
		t.Fatalf("expected Drupal 7.50 → critical CVE, got %+v", f)
	}
}

func TestBootstrapCVE(t *testing.T) {
	ar := analyzeBody(t, nil, `<script src="/assets/bootstrap-3.3.7.min.js"></script>`)
	f := findByProduct(ar.Findings, "bootstrap")
	if f == nil || len(f.CVE) == 0 {
		t.Fatalf("expected Bootstrap 3.3.7 CVE, got %+v", f)
	}
}

func TestGitHubTokenSecret(t *testing.T) {
	body := `{"cfg":{"key":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}}`
	ar := analyzeBody(t, nil, body)
	if !hasFindingType(ar.Findings, asset.FindingSecretExposure) {
		t.Errorf("expected GitHub token to be flagged, got %+v", ar.Findings)
	}
	// Evidence must be redacted — never echo the full token.
	for _, f := range ar.Findings {
		if f.Type == asset.FindingSecretExposure && strings.Contains(f.Evidence, "0123456789") {
			t.Errorf("secret evidence not redacted: %q", f.Evidence)
		}
	}
}

func TestLFIPasswdDetection(t *testing.T) {
	ar := analyzeBody(t, nil, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
	if !hasTitleContaining(ar.Findings, "Local File Inclusion") {
		t.Errorf("expected LFI /etc/passwd detection, got %+v", ar.Findings)
	}
}

func TestDotenvExposure(t *testing.T) {
	ar := analyzeBody(t, map[string]string{"content-type": "text/plain"},
		"APP_KEY=base64:abcd\nDB_PASSWORD=hunter2\n")
	if !hasTitleContaining(ar.Findings, "Environment File") {
		t.Errorf("expected .env exposure detection, got %+v", ar.Findings)
	}
}

func TestWerkzeugDebuggerDetection(t *testing.T) {
	ar := analyzeBody(t, nil, "<title>Werkzeug Debugger</title> The console is locked")
	if !hasTitleContaining(ar.Findings, "Werkzeug Debugger") {
		t.Errorf("expected Werkzeug debugger detection, got %+v", ar.Findings)
	}
}
