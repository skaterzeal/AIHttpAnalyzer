// Package output renders analysis results in the formats that matter for a
// pipeline tool: JSONL (default, pipes into the next tool), SARIF (CI/CD and
// GitHub code scanning), and Markdown (human report).
package output

import (
	"encoding/json"
	"io"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// Findings flattens results into a severity-filtered slice, preserving order.
func Findings(results []asset.AnalyzedResponse, min asset.Severity) []asset.Finding {
	var out []asset.Finding
	for _, ar := range results {
		for _, f := range ar.Findings {
			if f.Severity.AtLeast(min) {
				out = append(out, f)
			}
		}
	}
	return out
}

// aiRecord is the JSONL representation of advisory AI triage. It is a distinct
// record kind so consumers can tell ground-truth findings from AI advice.
type aiRecord struct {
	Asset  string          `json:"asset"`
	Kind   string          `json:"kind"`
	Triage *asset.AITriage `json:"triage"`
}

// WriteJSONL writes one Finding per line, then one ai_triage record per response
// that has AI advice. Findings stream cleanly into the next tool in the pipeline;
// AI records are clearly separated and never masquerade as ground truth.
func WriteJSONL(w io.Writer, results []asset.AnalyzedResponse, min asset.Severity) error {
	enc := json.NewEncoder(w)
	for _, f := range Findings(results, min) {
		if err := enc.Encode(f); err != nil {
			return err
		}
	}
	for _, ar := range results {
		if ar.AITriage == nil {
			continue
		}
		rec := aiRecord{Asset: assetID(ar), Kind: "ai_triage", Triage: ar.AITriage}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

// WriteAIRecord writes a single advisory ai_triage JSONL record. Used by the
// live proxy, which produces triage asynchronously after the deterministic
// findings have already been streamed.
func WriteAIRecord(w io.Writer, assetID string, tr *asset.AITriage) error {
	return json.NewEncoder(w).Encode(aiRecord{Asset: assetID, Kind: "ai_triage", Triage: tr})
}

// assetID returns the response's asset identifier for output records.
func assetID(ar asset.AnalyzedResponse) string {
	if ar.Response != nil {
		return ar.Response.AssetID()
	}
	return ""
}
