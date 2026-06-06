package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// WriteAttackSurfaceJSON writes the attack-surface map as a single JSON object.
func WriteAttackSurfaceJSON(w io.Writer, m asset.AttackSurfaceMap) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// WriteAttackSurfaceMarkdown writes a human-readable attack-surface report.
func WriteAttackSurfaceMarkdown(w io.Writer, m asset.AttackSurfaceMap) error {
	var b strings.Builder
	b.WriteString("# Attack Surface Map\n\n")
	if m.Target != "" {
		b.WriteString(fmt.Sprintf("**Target:** %s\n\n", m.Target))
	}
	b.WriteString(m.Summary + "\n\n")

	if len(m.CVEs) > 0 {
		b.WriteString("## Correlated CVEs\n\n")
		for _, c := range m.CVEs {
			b.WriteString("- " + c + "\n")
		}
		b.WriteString("\n")
	}

	if len(m.CriticalFindings) > 0 {
		b.WriteString("## High / Critical Findings\n\n")
		for _, f := range m.CriticalFindings {
			b.WriteString(fmt.Sprintf("- **[%s]** %s — `%s`",
				strings.ToUpper(string(f.Severity)), f.Title, f.Asset))
			if len(f.CVE) > 0 {
				b.WriteString(fmt.Sprintf(" (%s, CVSS %.1f)", strings.Join(f.CVE, ", "), f.CVSS))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if len(m.Technologies) > 0 {
		b.WriteString("## Technologies\n\n")
		b.WriteString(strings.Join(m.Technologies, ", ") + "\n\n")
	}

	if len(m.UniqueEndpoints) > 0 {
		b.WriteString(fmt.Sprintf("## Endpoints (%d)\n\n", len(m.UniqueEndpoints)))
		for _, e := range m.UniqueEndpoints {
			b.WriteString("- `" + e + "`\n")
		}
		b.WriteString("\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}
