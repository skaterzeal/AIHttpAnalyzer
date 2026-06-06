package extract

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

func TestExternalErrorSignatureOverridesEmbedded(t *testing.T) {
	dir := t.TempDir()
	custom := `signatures:
  - id: custom
    name: Custom Marker
    severity: medium
    patterns: ["XYZZY_MARKER"]
    implication: "custom community signature"
`
	if err := os.WriteFile(filepath.Join(dir, "error_signatures.yaml"), []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}

	e, err := NewErrorExtractor(Loader{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}

	// Custom signature is detected...
	hit := e.Extract(&asset.HTTPResponse{Body: "boom XYZZY_MARKER boom", Headers: map[string]string{}})
	if len(hit) != 1 || hit[0].Title != "Custom Marker" {
		t.Fatalf("expected custom signature, got %+v", hit)
	}
	// ...and the embedded MySQL signature is NOT, because the external file
	// fully overrides the embedded pack.
	none := e.Extract(&asset.HTTPResponse{Body: "You have an error in your SQL syntax", Headers: map[string]string{}})
	if len(none) != 0 {
		t.Errorf("external pack should override embedded, got %+v", none)
	}
}

func TestLoaderFallsBackToEmbeddedWhenFileMissing(t *testing.T) {
	dir := t.TempDir() // empty dir — no override files present
	e, err := NewStackTraceExtractor(Loader{Dir: dir})
	if err != nil {
		t.Fatalf("loader should fall back to embedded: %v", err)
	}
	if len(e.patterns) == 0 {
		t.Error("expected embedded stack patterns via fallback")
	}
}
