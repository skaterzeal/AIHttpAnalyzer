from __future__ import annotations

from src.core.models import HTTPResponse, ExtractedFinding


class ContextBuilder:
    """Build context strings for LLM prompts."""

    def build(
        self,
        response: HTTPResponse,
        findings: list[ExtractedFinding],
        previous_findings: list[ExtractedFinding] | None = None,
    ) -> str:
        """Build a rich context block for AI analysis."""
        lines = [
            f"URL: {response.request.url if response.request else 'N/A'}",
            f"Status: {response.status_code}",
            f"Content-Type: {response.content_type}",
            f"Size: {response.size_bytes} bytes",
            "",
            "Pre-extracted findings:",
        ]
        for f in findings:
            lines.append(f"- [{f.severity}] {f.title}: {f.detail[:120]}")
        if previous_findings:
            lines.append("")
            lines.append("Previous findings from other responses:")
            for f in previous_findings[:5]:
                lines.append(f"- [{f.severity}] {f.title}")
        return "\n".join(lines)
