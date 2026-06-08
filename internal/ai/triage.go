package ai

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

// Triager runs the advisory AI pass over an analyzed response.
type Triager struct {
	provider Provider
}

// NewTriager wraps a provider.
func NewTriager(p Provider) *Triager { return &Triager{provider: p} }

// Triage produces advisory triage for one analyzed response. An optional
// operator question focuses the analysis (used by the `ask` command). It NEVER
// mutates findings or severities — it only returns an AITriage. Injection
// detection runs regardless of the model's output, so a manipulated body is
// always flagged.
func (t *Triager) Triage(ctx context.Context, ar asset.AnalyzedResponse, question string) (*asset.AITriage, error) {
	injection := DetectInjection(ar.Response.Body)
	prompt := buildPrompt(ar, injection, question)

	raw, err := t.provider.Complete(ctx, prompt)
	if err != nil {
		return nil, err
	}

	parsed := parseTriageJSON(raw)
	parsed.Provider = t.provider.Name()
	// Operator-side detection wins: merge any model-reported injection with ours.
	parsed.InjectionDetected = mergeUnique(injection, parsed.InjectionDetected)
	return parsed, nil
}

// TriageBatch fills in AITriage for every result concurrently, bounded by
// concurrency. LLM calls are network-latency dominated, so a worker pool turns a
// long sequential wait into a parallel one. Failures leave that result's triage
// nil; it returns how many succeeded and the first error seen (for the caller to
// surface a single warning) so the deterministic report is never blocked.
func (t *Triager) TriageBatch(ctx context.Context, results []asset.AnalyzedResponse, concurrency int) (succeeded int, firstErr error) {
	if concurrency < 1 {
		concurrency = 1
	}
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		jobs = make(chan int)
	)
	worker := func() {
		defer wg.Done()
		for i := range jobs {
			tr, err := t.Triage(ctx, results[i], "")
			mu.Lock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
			} else {
				results[i].AITriage = tr
				succeeded++
			}
			mu.Unlock()
		}
	}
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go worker()
	}
	for i := range results {
		if results[i].Response == nil {
			continue
		}
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return succeeded, ctx.Err()
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()
	return succeeded, firstErr
}

type rawTriage struct {
	Summary             string   `json:"summary"`
	RecommendedTests    []string `json:"recommended_tests"`
	UnverifiedEndpoints []string `json:"unverified_endpoints"`
	Reasoning           string   `json:"reasoning"`
}

// parseTriageJSON extracts the JSON object from a model response, tolerating
// code fences and surrounding prose. On failure it degrades gracefully to a
// summary-only result rather than erroring the whole run.
func parseTriageJSON(raw string) *asset.AITriage {
	clean := strings.TrimSpace(raw)
	clean = strings.ReplaceAll(clean, "```json", "")
	clean = strings.ReplaceAll(clean, "```", "")

	var rt rawTriage
	if err := json.Unmarshal([]byte(clean), &rt); err != nil {
		// Fall back to the substring between the first { and last }.
		if i, j := strings.Index(clean, "{"), strings.LastIndex(clean, "}"); i >= 0 && j > i {
			if err2 := json.Unmarshal([]byte(clean[i:j+1]), &rt); err2 != nil {
				return &asset.AITriage{Summary: truncateStr(strings.TrimSpace(raw), 400)}
			}
		} else {
			return &asset.AITriage{Summary: truncateStr(strings.TrimSpace(raw), 400)}
		}
	}
	return &asset.AITriage{
		Summary:             rt.Summary,
		RecommendedTests:    rt.RecommendedTests,
		UnverifiedEndpoints: rt.UnverifiedEndpoints,
		Reasoning:           rt.Reasoning,
	}
}

func mergeUnique(a, b []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
