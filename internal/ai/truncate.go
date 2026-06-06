package ai

import (
	"sort"
	"strings"

	"github.com/skaterzeal/AIHttpAnalyzer/pkg/asset"
)

type segment struct{ start, end int }

// smartTruncate shrinks a body for the LLM while preserving the parts that
// matter: the head and tail (structure) and windows around each finding's
// evidence. This keeps the signal the deterministic engine already found while
// staying within token budgets.
func smartTruncate(body string, findings []asset.Finding, maxLen int) string {
	if len(body) <= maxLen {
		return body
	}

	const edge = 400
	const window = 200

	segs := []segment{
		{0, min(edge, len(body))},
		{max(0, len(body)-edge), len(body)},
	}
	for _, f := range findings {
		if f.Evidence == "" {
			continue
		}
		from := 0
		for {
			i := strings.Index(body[from:], f.Evidence)
			if i < 0 {
				break
			}
			idx := from + i
			segs = append(segs, segment{
				start: max(0, idx-window),
				end:   min(len(body), idx+len(f.Evidence)+window),
			})
			from = idx + len(f.Evidence)
			if from >= len(body) {
				break
			}
		}
	}

	merged := mergeSegments(segs)

	var b strings.Builder
	last := 0
	for i, s := range merged {
		if i > 0 && s.start > last {
			b.WriteString("\n...[snip]...\n")
		}
		b.WriteString(body[s.start:s.end])
		last = s.end
	}
	return b.String()
}

func mergeSegments(segs []segment) []segment {
	if len(segs) == 0 {
		return nil
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].start < segs[j].start })
	out := []segment{segs[0]}
	for _, s := range segs[1:] {
		last := &out[len(out)-1]
		if s.start <= last.end {
			if s.end > last.end {
				last.end = s.end
			}
		} else {
			out = append(out, s)
		}
	}
	return out
}
