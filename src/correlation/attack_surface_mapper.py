from __future__ import annotations

from datetime import datetime, timezone

from src.core.models import AnalyzedResponse, AttackSurfaceMap, Severity


class AttackSurfaceMapper:
    """Build an attack surface map from analyzed responses."""

    def build_map(
        self,
        analyzed_responses: list[AnalyzedResponse],
    ) -> AttackSurfaceMap:
        """
        Tüm response analizlerini birleştirip hedefin
        saldırı yüzeyi haritasını çıkar.
        """
        all_endpoints = set()
        all_tech = {}
        critical_items = []

        for ar in analyzed_responses:
            all_endpoints.update(ar.endpoints_found)
            for tech in ar.technologies:
                all_tech[tech] = tech

            for f in ar.findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    critical_items.append(f)

            if ar.ai_analysis:
                if ar.ai_analysis.hidden_endpoints:
                    all_endpoints.update(ar.ai_analysis.hidden_endpoints)
                if ar.ai_analysis.technologies_detected:
                    for tech in ar.ai_analysis.technologies_detected:
                        all_tech[tech] = tech


        # AI ile toplu özet oluştur
        ai_summary = self._generate_summary(analyzed_responses)

        target = ""
        if analyzed_responses and analyzed_responses[0].response.request:
            try:
                from tldextract import extract as tld_extract

                t = tld_extract(analyzed_responses[0].response.request.url)
                if hasattr(t, "top_domain_under_public_suffix"):
                    target = t.top_domain_under_public_suffix
                else:
                    target = t.registered_domain
            except Exception:
                target = analyzed_responses[0].response.request.url

        return AttackSurfaceMap(
            target=target,
            total_responses=len(analyzed_responses),
            unique_endpoints=sorted(all_endpoints),
            technologies=all_tech,
            critical_findings=critical_items,
            ai_summary=ai_summary,
            generated_at=datetime.now(timezone.utc),
        )

    def _generate_summary(self, analyzed_responses: list[AnalyzedResponse]) -> str:
        total = len(analyzed_responses)
        techs = set()
        endpoints = set()
        crit = 0
        high = 0
        for ar in analyzed_responses:
            techs.update(ar.technologies)
            endpoints.update(ar.endpoints_found)
            for f in ar.findings:
                if f.severity == Severity.CRITICAL:
                    crit += 1
                elif f.severity == Severity.HIGH:
                    high += 1
        return (
            f"{total} response analiz edildi. "
            f"{len(endpoints)} benzersiz endpoint, {len(techs)} teknoloji tespit edildi. "
            f"{crit} critical, {high} high seviyeli bulgu."
        )
