package extract

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// patternFS holds the built-in detection pattern packs. They are embedded so the
// binary is fully self-contained, but every loader also accepts an external
// directory so users can ship their own community pattern packs (nuclei-style).
//
//go:embed patterns/*.yaml
var patternFS embed.FS

// --- stack traces ---

type stackPattern struct {
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	Severity      string   `yaml:"severity"`
	Regex         string   `yaml:"regex"`
	Frameworks    []string `yaml:"frameworks"`
	ExtractFields []string `yaml:"extract_fields"`
}

type stackPatternFile struct {
	Patterns []stackPattern `yaml:"patterns"`
}

// --- version disclosure ---

type versionPattern struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	Severity   string `yaml:"severity"`
	Source     string `yaml:"source"`
	HeaderName string `yaml:"header_name"`
	Regex      string `yaml:"regex"`
	Product    string `yaml:"product"`
	Context    string `yaml:"context"`
}

type versionPatternFile struct {
	Patterns []versionPattern `yaml:"patterns"`
}

// --- error signatures ---

type errorSignature struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Patterns    []string `yaml:"patterns"`
	Implication string   `yaml:"implication"`
}

type errorSignatureFile struct {
	Signatures []errorSignature `yaml:"signatures"`
}

// --- technology fingerprints ---

type fpHeaderIndicator struct {
	Name    string `yaml:"name"`
	Value   string `yaml:"value"`
	Pattern string `yaml:"pattern"`
}

type fingerprint struct {
	Name       string `yaml:"name"`
	Indicators struct {
		Headers []fpHeaderIndicator `yaml:"headers"`
		Body    []string            `yaml:"body"`
	} `yaml:"indicators"`
	VersionFrom string `yaml:"version_from"`
}

type fingerprintFile struct {
	Fingerprints []fingerprint `yaml:"fingerprints"`
}

// Loader reads pattern packs. When Dir is set, a file of the same name there
// overrides the embedded pack — this is how users ship community/custom pattern
// packs (nuclei-template style) without rebuilding the binary.
type Loader struct {
	Dir string
}

// load reads and unmarshals one pattern file into out, preferring the external
// directory over the embedded pack when present.
func (l Loader) load(name string, out any) error {
	var data []byte
	var err error
	if l.Dir != "" {
		p := filepath.Join(l.Dir, name)
		if data, err = os.ReadFile(p); err == nil {
			if uerr := yaml.Unmarshal(data, out); uerr != nil {
				return fmt.Errorf("parse external pattern %s: %w", p, uerr)
			}
			return nil
		}
		// Fall back to embedded when the file is absent in the external dir.
	}
	data, err = patternFS.ReadFile("patterns/" + name)
	if err != nil {
		return fmt.Errorf("read embedded pattern %s: %w", name, err)
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parse pattern %s: %w", name, err)
	}
	return nil
}
