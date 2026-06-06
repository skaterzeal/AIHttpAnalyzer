package extract

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/internal/httpparse"
	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func loadFixture(t *testing.T, name string) *asset.HTTPResponse {
	t.Helper()
	path := filepath.Join("..", "..", "tests", "fixtures", "sample_responses", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return httpparse.ParseResponse(string(raw), "file")
}

func hasFindingType(fs []asset.Finding, ft asset.FindingType) bool {
	for _, f := range fs {
		if f.Type == ft {
			return true
		}
	}
	return false
}

func hasTitleContaining(fs []asset.Finding, sub string) bool {
	for _, f := range fs {
		if contains(f.Title, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func hasTech(techs []string, name string) bool {
	for _, t := range techs {
		if t == name {
			return true
		}
	}
	return false
}

func newEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestDjangoDebugFixture(t *testing.T) {
	e := newEngine(t)
	ar := e.Analyze(loadFixture(t, "django_debug.http"))

	if !hasFindingType(ar.Findings, asset.FindingStackTrace) {
		t.Error("expected a stack trace finding")
	}
	if !hasTech(ar.Technologies, "Django") {
		t.Errorf("expected Django in technologies, got %v", ar.Technologies)
	}
}

func TestLaravelErrorFixture(t *testing.T) {
	e := newEngine(t)
	ar := e.Analyze(loadFixture(t, "laravel_error.http"))

	if !hasFindingType(ar.Findings, asset.FindingStackTrace) {
		t.Error("expected a PHP stack trace finding")
	}
	if !hasTech(ar.Technologies, "Laravel") {
		t.Errorf("expected Laravel in technologies, got %v", ar.Technologies)
	}
}

func TestSpringActuatorFixture(t *testing.T) {
	e := newEngine(t)
	ar := e.Analyze(loadFixture(t, "spring_actuator.http"))

	if !hasTitleContaining(ar.Findings, "Actuator") {
		t.Errorf("expected Spring Actuator finding, got %+v", ar.Findings)
	}
	if !hasTech(ar.Technologies, "Spring Boot") {
		t.Errorf("expected Spring Boot in technologies, got %v", ar.Technologies)
	}
}

func TestGraphQLIntrospectionFixture(t *testing.T) {
	e := newEngine(t)
	ar := e.Analyze(loadFixture(t, "graphql_introspection.http"))

	if !hasTitleContaining(ar.Findings, "GraphQL") {
		t.Errorf("expected GraphQL introspection finding, got %+v", ar.Findings)
	}
}

func TestSecretEntropyFilter(t *testing.T) {
	e := newEngine(t)
	// A low-entropy placeholder must NOT be reported; a real high-entropy key must.
	body := `{"api_key":"aaaaaaaaaaaaaaaa","token":"aaaaaaaaaaaa","real":"x"}`
	r := &asset.HTTPResponse{Body: body, Headers: map[string]string{}, Source: "test"}
	for _, f := range e.Analyze(r).Findings {
		if f.Type == asset.FindingSecretExposure {
			t.Errorf("low-entropy value should not be flagged: %+v", f)
		}
	}

	// High-entropy, synthetic value with no provider prefix (so it is not a real
	// secret and does not trip upstream secret scanners), still flagged by the
	// generic api_key detector.
	body2 := `{"api_key":"Zk7Qd2Xp9Lm4Rt6Yw3Bn8Vc1Hs5Jf0Ae"}`
	r2 := &asset.HTTPResponse{Body: body2, Headers: map[string]string{}, Source: "test"}
	if !hasFindingType(e.Analyze(r2).Findings, asset.FindingSecretExposure) {
		t.Error("high-entropy api key should be flagged")
	}
}

func TestCVECorrelationApacheVuln(t *testing.T) {
	e := newEngine(t)
	ar := e.Analyze(loadFixture(t, "apache_vuln.http"))

	var apacheCVE, phpCVE *asset.Finding
	for i := range ar.Findings {
		f := &ar.Findings[i]
		if f.Product == "apache" && f.Version == "2.4.49" {
			apacheCVE = f
		}
		if f.Product == "php" && f.Version == "8.1.0" {
			phpCVE = f
		}
	}
	if apacheCVE == nil {
		t.Fatalf("apache 2.4.49 version finding missing: %+v", ar.Findings)
	}
	if len(apacheCVE.CVE) == 0 || apacheCVE.Severity != asset.SeverityCritical {
		t.Errorf("apache should be CVE-correlated and critical, got %+v", apacheCVE)
	}
	if phpCVE == nil || len(phpCVE.CVE) == 0 {
		t.Errorf("php 8.1.0 should be CVE-correlated, got %+v", phpCVE)
	}
}

func TestVersionAndServerHeader(t *testing.T) {
	e := newEngine(t)
	r := &asset.HTTPResponse{
		Headers: map[string]string{"server": "nginx/1.18.0"},
		Body:    "",
		Source:  "test",
	}
	if !hasFindingType(e.Analyze(r).Findings, asset.FindingVersionDisclosure) {
		t.Error("expected version disclosure from Server header")
	}
}
