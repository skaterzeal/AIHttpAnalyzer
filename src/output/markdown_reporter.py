from __future__ import annotations

from pathlib import Path
from datetime import datetime

from src.core.models import AnalyzedResponse, AttackSurfaceMap, Severity


class MarkdownReporter:
    """Generate Markdown reports from analysis results."""

    def report(
        self,
        results: list[AnalyzedResponse],
        output_path: str | Path,
    ) -> None:
        """Generate a Markdown report of findings."""
        lines = [
            "# HTTP Response Analyzer Raporu\n",
            f"**Tarih:** {datetime.utcnow().isoformat()}\n",
            f"**Toplam Response:** {len(results)}\n",
            "---\n",
        ]

        severity_counts = {s: 0 for s in Severity}
        for ar in results:
            for f in ar.findings:
                severity_counts[f.severity] += 1

        lines.append("## Bulgu Özeti\n")
        for sev in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"- **{sev.value.upper()}**: {count}\n")

        lines.append("\n## Detaylı Bulgular\n")
        for ar in results:
            url = ar.response.request.url if ar.response.request else "N/A"
            lines.append(f"\n### {url} (Status: {ar.response.status_code})\n")
            for f in ar.findings:
                lines.append(f"- [{f.severity.value}] **{f.title}**\n")
                lines.append(f"  - {f.detail}\n")
                lines.append(f"  - Evidence: `{f.evidence[:200]}`\n")

            if ar.ai_analysis:
                lines.append(f"\n**AI Özeti:** {ar.ai_analysis.summary}\n")
                lines.append(f"**Risk Seviyesi:** {ar.ai_analysis.risk_level.value}\n")
                if ar.ai_analysis.recommended_tests:
                    lines.append("**Önerilen Testler:**\n")
                    for t in ar.ai_analysis.recommended_tests:
                        lines.append(f"- {t}\n")

        Path(output_path).write_text("".join(lines), encoding="utf-8")

    def report_attack_surface(
        self,
        attack_surface: AttackSurfaceMap,
        output_path: str | Path,
    ) -> None:
        """Generate a Markdown attack surface map."""
        lines = [
            f"# Saldırı Yüzeyi Haritası: {attack_surface.target}\n",
            f"**Toplam Response:** {attack_surface.total_responses}\n",
            f"**Tarih:** {attack_surface.generated_at.isoformat()}\n",
            "---\n",
            "## Teknolojiler\n",
        ]
        for tech in attack_surface.technologies:
            lines.append(f"- {tech}\n")

        lines.append("\n## Benzersiz Endpoint'ler\n")
        for ep in attack_surface.unique_endpoints:
            lines.append(f"- `{ep}`\n")

        lines.append("\n## Kritik Bulgular\n")
        for f in attack_surface.critical_findings:
            lines.append(f"- [{f.severity.value}] **{f.title}** — {f.detail[:200]}\n")

        lines.append(f"\n## AI Özeti\n{attack_surface.ai_summary}\n")
        Path(output_path).write_text("".join(lines), encoding="utf-8")
