package output

import (
	"encoding/json"
	"io"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// Minimal SARIF 2.1.0 model — enough for CI/CD ingestion and GitHub code scanning.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel maps a severity to a SARIF level.
func sarifLevel(s asset.Severity) string {
	switch s {
	case asset.SeverityCritical, asset.SeverityHigh:
		return "error"
	case asset.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF renders findings as a SARIF log.
func WriteSARIF(w io.Writer, results []asset.AnalyzedResponse, min asset.Severity, toolVersion string) error {
	findings := Findings(results, min)

	ruleSet := map[string]struct{}{}
	var rules []sarifRule
	var sresults []sarifResult
	for _, f := range findings {
		id := string(f.Type)
		if _, ok := ruleSet[id]; !ok {
			ruleSet[id] = struct{}{}
			rules = append(rules, sarifRule{ID: id})
		}
		msg := f.Title
		if f.Detail != "" {
			msg += " — " + f.Detail
		}
		sresults = append(sresults, sarifResult{
			RuleID:  id,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Asset},
				},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    "httpanalyzer",
				Version: toolVersion,
				Rules:   rules,
			}},
			Results: sresults,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
