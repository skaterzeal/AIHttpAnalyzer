from __future__ import annotations

from pydantic import BaseModel
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    ENDPOINT_DISCOVERED = "endpoint_discovered"
    STACK_TRACE = "stack_trace"
    VERSION_DISCLOSURE = "version_disclosure"
    SECRET_EXPOSURE = "secret_exposure"
    ERROR_MESSAGE = "error_message"
    DEBUG_INFO = "debug_info"
    TECHNOLOGY_DETECTED = "technology_detected"
    MISCONFIG_DETECTED = "misconfig_detected"
    EXPLOIT_OPPORTUNITY = "exploit_opportunity"


class HTTPRequest(BaseModel):
    method: str
    url: str
    path: str
    headers: dict[str, str]
    body: str | None
    timestamp: datetime | None


class HTTPResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str | None
    size_bytes: int
    response_time_ms: float | None
    request: HTTPRequest | None
    source: str  # "burp", "file", "proxy", "direct"


class ExtractedFinding(BaseModel):
    id: str
    finding_type: FindingType
    severity: Severity
    title: str
    detail: str
    evidence: str  # response'tan alınan snippet
    location: str  # header adı / body XPath / satır no
    response_id: str
    confidence: float  # 0.0 – 1.0


class AIAnalysisResult(BaseModel):
    response_id: str
    summary: str  # 2-3 cümle genel değerlendirme
    exploitable_findings: list[str]
    recommended_tests: list[str]  # "SQLi dene", "IDOR test et" vb.
    risk_level: Severity
    reasoning: str
    raw_llm_output: str
    hidden_endpoints: list[str] = []
    technologies_detected: list[str] = []
    security_headers_missing: list[str] = []



class AnalyzedResponse(BaseModel):
    response_id: str
    response: HTTPResponse
    findings: list[ExtractedFinding]
    ai_analysis: AIAnalysisResult | None
    endpoints_found: list[str]
    technologies: list[str]
    analyzed_at: datetime


class AttackSurfaceMap(BaseModel):
    target: str
    total_responses: int
    unique_endpoints: list[str]
    technologies: dict[str, str]  # {"framework": "Django 3.2", ...}
    critical_findings: list[ExtractedFinding]
    ai_summary: str
    generated_at: datetime
