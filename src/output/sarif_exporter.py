from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime

from src.core.models import AnalyzedResponse, Severity


class SARIFExporter:
    """Export findings to SARIF (Static Analysis Results Interchange Format)."""

    def export(
        self,
        results: list[AnalyzedResponse],
        output_path: str | Path,
    ) -> None:
        """Write findings to a SARIF JSON file."""
        rules = []
        rule_ids = set()
        findings_list = []

        for ar in results:
            url = ar.response.request.url if ar.response.request else "unknown"
            for f in ar.findings:
                rule_id = f.finding_type.value
                if rule_id not in rule_ids:
                    rule_ids.add(rule_id)
                    rules.append(
                        {
                            "id": rule_id,
                            "name": f.title,
                            "shortDescription": {"text": f.detail[:200]},
                        }
                    )
                findings_list.append(
                    {
                        "ruleId": rule_id,
                        "level": self._severity_to_level(f.severity),
                        "message": {"text": f.detail},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": url},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                )

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "HTTP Response Analyzer",
                            "version": "0.1.0",
                        }
                    },
                    "results": findings_list,
                    "rules": rules,
                }
            ],
        }

        Path(output_path).write_text(
            json.dumps(sarif, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _severity_to_level(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")
