from __future__ import annotations

import re
import uuid
from pathlib import Path

import yaml

from src.core.models import HTTPResponse, ExtractedFinding, FindingType, Severity


class ErrorExtractor:
    """Extract error signatures and debug information from HTTP responses."""

    def __init__(self, signatures_path: str | None = None):
        if signatures_path is None:
            signatures_path = (
                Path(__file__).resolve().parents[2]
                / "data"
                / "patterns"
                / "error_signatures.yaml"
            )
        with open(signatures_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.signatures = data.get("signatures", [])

    def extract(self, response: HTTPResponse) -> list[ExtractedFinding]:
        """Scan response for known error signatures."""
        findings = []
        body = response.body

        for sig in self.signatures:
            matched = False
            matched_pattern = ""
            for pattern in sig.get("patterns", []):
                try:
                    if re.search(pattern, body, re.IGNORECASE):
                        matched = True
                        matched_pattern = pattern
                        break
                except re.error:
                    # Fallback to literal case-insensitive search
                    if pattern.lower() in body.lower():
                        matched = True
                        matched_pattern = pattern
                        break

            if matched:
                findings.append(
                    ExtractedFinding(
                        id=str(uuid.uuid4()),
                        finding_type=FindingType.ERROR_MESSAGE,
                        severity=Severity(sig.get("severity", "medium")),
                        title=sig["name"],
                        detail=sig.get("implication", ""),
                        evidence=matched_pattern,
                        location="body",
                        response_id="",
                        confidence=0.85,
                    )
                )

        return findings
