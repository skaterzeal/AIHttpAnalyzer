package extract

import "math"

// truncate shortens s to at most n bytes, appending an ellipsis marker when cut.
// It is byte-safe for ASCII evidence; multi-byte runes at the boundary are
// tolerated since evidence is advisory, not parsed downstream.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// dedupe returns the input with duplicates removed, preserving first-seen order.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0:0]
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// shannonEntropy returns the Shannon entropy (bits per symbol) of s, used to
// distinguish real secrets from low-entropy placeholder values.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, c := range s {
		counts[c]++
	}
	n := float64(len([]rune(s)))
	var entropy float64
	for _, c := range counts {
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
