from __future__ import annotations

import re
import uuid
from pathlib import Path

import yaml

from src.core.models import HTTPResponse, ExtractedFinding, FindingType, Severity


class VersionExtractor:
    """Extract version disclosures from HTTP headers and body."""

    def __init__(self, patterns_path: str | None = None):
        if patterns_path is None:
            patterns_path = Path(__file__).resolve().parents[2] / "data" / "patterns" / "version_patterns.yaml"
        with open(patterns_path, "r", encoding="utf-8") as f:
            self.patterns = yaml.safe_load(f)["patterns"]

    def extract(self, response: HTTPResponse) -> list[ExtractedFinding]:
        """Scan response for version information."""
        findings = []

        for pat in self.patterns:
            source = pat["source"]
            target_text = ""

            if source == "header":
                target_text = response.headers.get(pat.get("header_name", ""), "")
            elif source == "body":
                target_text = response.body

            m = re.search(pat["regex"], target_text, re.IGNORECASE)
            if not m:
                continue

            version = m.group(1) if m.lastindex else m.group(0)

            findings.append(
                ExtractedFinding(
                    id=str(uuid.uuid4()),
                    finding_type=FindingType.VERSION_DISCLOSURE,
                    severity=Severity(pat["severity"]),
                    title=pat["name"],
                    detail=f"Tespit edilen versiyon: {version}",
                    evidence=m.group(0),
                    location=f"{source}:{pat.get('header_name', 'body')}",
                    response_id="",
                    confidence=0.90,
                )
            )

        return findings
