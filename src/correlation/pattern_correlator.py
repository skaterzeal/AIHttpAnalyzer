from __future__ import annotations

from src.core.models import ExtractedFinding


class PatternCorrelator:
    """Correlate findings across multiple responses to identify patterns."""

    def correlate(self, findings: list[ExtractedFinding]) -> dict:
        """Group findings by type and severity to spot recurring issues."""
        groups: dict[str, list[ExtractedFinding]] = {}
        for f in findings:
            key = f"{f.finding_type.value}:{f.severity.value}"
            groups.setdefault(key, []).append(f)
        return groups
