// Package asset defines the shared domain types that form the interop contract
// for the recon/triage ecosystem. Tools communicate over JSONL using these
// types: DNSRecon (and other producers) emit [Asset] lines; httpanalyzer
// consumes them and emits [Finding] lines that the next tool in the pipeline
// can read.
package asset

import (
	"strings"
	"time"
)

// Severity is the canonical risk level for a finding. Severities are always
// assigned by the deterministic engine or CVE correlation — never invented by
// the AI layer.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// severityRank orders severities from least to most severe so they can be
// compared and filtered (e.g. --min-severity).
var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Rank returns the ordinal of the severity (info=0 .. critical=4). Unknown
// severities rank as info.
func (s Severity) Rank() int { return severityRank[s] }

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() >= min.Rank() }

// ParseSeverity normalizes a string into a Severity, falling back to
// SeverityInfo for unknown values.
func ParseSeverity(v string) Severity {
	s := Severity(strings.ToLower(strings.TrimSpace(v)))
	if s.Valid() {
		return s
	}
	return SeverityInfo
}

// FindingType categorizes what a finding represents.
type FindingType string

const (
	FindingEndpointDiscovered FindingType = "endpoint_discovered"
	FindingStackTrace         FindingType = "stack_trace"
	FindingVersionDisclosure  FindingType = "version_disclosure"
	FindingSecretExposure     FindingType = "secret_exposure"
	FindingErrorMessage       FindingType = "error_message"
	FindingDebugInfo          FindingType = "debug_info"
	FindingTechnologyDetected FindingType = "technology_detected"
	FindingMisconfig          FindingType = "misconfig_detected"
	FindingExploitOpportunity FindingType = "exploit_opportunity"
)

// Source identifies which subsystem produced a finding. This lets consumers
// trust deterministic/cve findings as ground truth while treating ai findings
// as advisory.
const (
	SourceDeterministic = "deterministic"
	SourceCVE           = "cve"
	SourceAI            = "ai"
)

// Asset is a single target to analyze. It is the JSONL input unit produced by
// DNSRecon or any upstream tool. Plain "host" or "url" text lines are also
// accepted by the ingester and converted into an Asset.
type Asset struct {
	URL        string   `json:"url,omitempty"`
	Host       string   `json:"host,omitempty"`
	IP         string   `json:"ip,omitempty"`
	HTTPStatus int      `json:"http_status,omitempty"`
	Source     string   `json:"source,omitempty"`
	RiskScore  int      `json:"risk_score,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// Finding is the JSONL output unit. Each line emitted by httpanalyzer is one
// Finding, so results stream cleanly into the next tool in the pipeline.
type Finding struct {
	Asset      string      `json:"asset"`
	Type       FindingType `json:"type"`
	Severity   Severity    `json:"severity"`
	Title      string      `json:"title"`
	Detail     string      `json:"detail,omitempty"`
	Evidence   string      `json:"evidence,omitempty"`
	Location   string      `json:"location,omitempty"`
	Product    string      `json:"product,omitempty"`
	Version    string      `json:"version,omitempty"`
	CVE        []string    `json:"cve,omitempty"`
	CVSS       float64     `json:"cvss,omitempty"`
	Confidence float64     `json:"confidence"`
	Source     string      `json:"source"`
}

// HTTPRequest is the captured request side of an exchange.
type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// HTTPResponse is the unit the extraction engine analyzes. Ingesters from every
// source (Burp XML, .http files, live proxy, direct request, stdin) normalize
// into this type.
type HTTPResponse struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ContentType string            `json:"content_type,omitempty"`
	SizeBytes   int               `json:"size_bytes"`
	Request     *HTTPRequest      `json:"request,omitempty"`
	Source      string            `json:"source"`
}

// AssetID returns a stable identifier for the response, preferring the request
// URL and falling back to the source label.
func (r *HTTPResponse) AssetID() string {
	if r.Request != nil && r.Request.URL != "" {
		return r.Request.URL
	}
	return r.Source
}

// AITriage is the advisory output of the AI layer. It explains and prioritizes
// the deterministic findings and suggests follow-up tests. It deliberately
// carries no severity field: severity is owned by the deterministic engine and
// CVE correlation. AI-suggested endpoints are kept here as explicitly
// unverified and are never merged into the verified attack surface.
type AITriage struct {
	Provider            string   `json:"provider"`
	Summary             string   `json:"summary"`
	RecommendedTests    []string `json:"recommended_tests,omitempty"`
	UnverifiedEndpoints []string `json:"unverified_endpoints,omitempty"`
	InjectionDetected   []string `json:"injection_detected,omitempty"`
	Reasoning           string   `json:"reasoning,omitempty"`
}

// AnalyzedResponse bundles a response with everything derived from it.
type AnalyzedResponse struct {
	Response     *HTTPResponse `json:"response"`
	Findings     []Finding     `json:"findings"`
	Endpoints    []string      `json:"endpoints,omitempty"`
	Technologies []string      `json:"technologies,omitempty"`
	AITriage     *AITriage     `json:"ai_triage,omitempty"`
	AnalyzedAt   time.Time     `json:"analyzed_at"`
}

// AttackSurfaceMap is the aggregated, cross-asset view of an engagement: the
// deduplicated endpoints, technology inventory, correlated CVEs, and the
// highest-impact findings across every analyzed response.
type AttackSurfaceMap struct {
	Target           string    `json:"target,omitempty"`
	TotalResponses   int       `json:"total_responses"`
	UniqueEndpoints  []string  `json:"unique_endpoints,omitempty"`
	Technologies     []string  `json:"technologies,omitempty"`
	CVEs             []string  `json:"cves,omitempty"`
	CriticalFindings []Finding `json:"critical_findings,omitempty"`
	Summary          string    `json:"summary"`
	GeneratedAt      time.Time `json:"generated_at"`
}
