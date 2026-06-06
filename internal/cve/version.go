package cve

import (
	"strconv"
	"strings"
)

// parseVersion splits a dotted version into numeric components. Non-numeric
// segments (e.g. "1.2.3-beta") contribute their leading integer or 0.
func parseVersion(s string) []int {
	fields := strings.Split(strings.TrimSpace(s), ".")
	out := make([]int, len(fields))
	for i, f := range fields {
		out[i] = leadingInt(f)
	}
	return out
}

// leadingInt parses the leading integer of f, ignoring any trailing suffix.
func leadingInt(f string) int {
	end := 0
	for end < len(f) && f[end] >= '0' && f[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[:end])
	return n
}

// compareVersions returns -1, 0, or 1 comparing a and b component-wise. Missing
// trailing components are treated as 0, so "1.2" == "1.2.0".
func compareVersions(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va != vb {
			if va < vb {
				return -1
			}
			return 1
		}
	}
	return 0
}

// satisfies reports whether version meets every comma-separated clause in the
// constraint. Supported operators: <, <=, >, >=, = (bare version implies =).
// Clauses are ANDed, so ">=2.4.49,<2.4.51" means a half-open range.
func satisfies(version, constraint string) bool {
	for _, clause := range strings.Split(constraint, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		op, ver := splitClause(clause)
		c := compareVersions(version, ver)
		ok := false
		switch op {
		case "<":
			ok = c < 0
		case "<=":
			ok = c <= 0
		case ">":
			ok = c > 0
		case ">=":
			ok = c >= 0
		default: // "=" or bare
			ok = c == 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// splitClause separates the operator prefix from the version in a clause.
func splitClause(clause string) (op, version string) {
	switch {
	case strings.HasPrefix(clause, "<="):
		return "<=", strings.TrimSpace(clause[2:])
	case strings.HasPrefix(clause, ">="):
		return ">=", strings.TrimSpace(clause[2:])
	case strings.HasPrefix(clause, "<"):
		return "<", strings.TrimSpace(clause[1:])
	case strings.HasPrefix(clause, ">"):
		return ">", strings.TrimSpace(clause[1:])
	case strings.HasPrefix(clause, "="):
		return "=", strings.TrimSpace(clause[1:])
	default:
		return "=", clause
	}
}
