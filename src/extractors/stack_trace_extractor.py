from __future__ import annotations

import re
import uuid
from pathlib import Path

import yaml

from src.core.models import HTTPResponse, ExtractedFinding, FindingType, Severity


class StackTraceExtractor:
    """Extract stack traces and error messages from HTTP responses."""

    def __init__(self, patterns_path: str | None = None):
        if patterns_path is None:
            patterns_path = Path(__file__).resolve().parents[2] / "data" / "patterns" / "stack_traces.yaml"
        with open(patterns_path, "r", encoding="utf-8") as f:
            self.patterns = yaml.safe_load(f)["patterns"]

    def extract(self, response: HTTPResponse) -> list[ExtractedFinding]:
        """Scan response body for stack traces."""
        findings = []
        body = response.body

        for pat in self.patterns:
            m = re.search(pat["regex"], body, re.MULTILINE | re.DOTALL)
            if not m:
                continue

            raw_trace = m.group(0)
            fields = self._extract_fields(raw_trace, pat.get("extract_fields", []))

            findings.append(
                ExtractedFinding(
                    id=str(uuid.uuid4()),
                    finding_type=FindingType.STACK_TRACE,
                    severity=Severity(pat["severity"]),
                    title=pat["name"],
                    detail=(
                        f"Framework: {', '.join(pat.get('frameworks', []))}\n"
                        f"Çıkarılan bilgiler: {fields}"
                    ),
                    evidence=raw_trace[:500],
                    location="body",
                    response_id=response.source,
                    confidence=0.95,
                )
            )

        return findings

    def _extract_fields(self, trace: str, field_names: list[str]) -> dict:
        fields = {}
        if "file_paths" in field_names:
            fields["file_paths"] = re.findall(
                r"(?:/[a-zA-Z0-9_\-./]+\.(?:py|php|java|rb|js|ts|cs))", trace
            )
        if "line_numbers" in field_names:
            fields["line_numbers"] = re.findall(r"line (\d+)", trace)
        if "exception_type" in field_names:
            m = re.search(r"([A-Za-z]+(?:Error|Exception|Warning))", trace)
            if m:
                fields["exception_type"] = m.group(1)
        return fields
