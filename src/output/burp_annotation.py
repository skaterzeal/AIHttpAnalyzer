from __future__ import annotations

from lxml import etree

from src.core.models import AnalyzedResponse


def annotate_burp_xml(
    original_xml: str,
    analysis_results: list[AnalyzedResponse],
    output_path: str,
) -> None:
    """
    Orijinal Burp XML'ine AI analiz notlarını ekle.
    Burp Suite'e tekrar import edilebilir.

    Her item'a:
    - <comment>: Bulgu özeti
    - <highlight>: Severity'ye göre renk (red/orange/yellow/green)
    """
    COLORS = {
        "critical": "red",
        "high": "orange",
        "medium": "yellow",
        "low": "green",
        "info": "gray",
    }

    tree = etree.parse(original_xml)
    items = tree.findall(".//item")

    result_map = {
        ar.response.request.url: ar
        for ar in analysis_results
        if ar.response.request
    }

    for item in items:
        url = item.findtext("url") or ""
        ar = result_map.get(url)
        if not ar:
            continue

        top_severity = "info"
        if ar.ai_analysis:
            top_severity = ar.ai_analysis.risk_level.value

        comment = etree.SubElement(item, "comment")
        findings = [f.title for f in ar.findings[:3]]
        comment.text = (
            f"[AI] {ar.ai_analysis.summary[:100] if ar.ai_analysis else ''} | {', '.join(findings)}"
        )

        highlight = etree.SubElement(item, "highlight")
        highlight.text = COLORS.get(top_severity, "gray")

    tree.write(output_path, xml_declaration=True, encoding="utf-8")
