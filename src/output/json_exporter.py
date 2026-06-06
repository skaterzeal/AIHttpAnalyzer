from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime

from src.core.models import AnalyzedResponse, AttackSurfaceMap


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class JSONExporter:
    """Export analysis results to JSON."""

    def export(
        self,
        results: list[AnalyzedResponse],
        output_path: str | Path,
    ) -> None:
        """Write analyzed responses to a JSON file."""
        data = [r.model_dump(mode="json") for r in results]
        Path(output_path).write_text(
            json.dumps(data, indent=2, cls=JSONEncoder, ensure_ascii=False),
            encoding="utf-8",
        )

    def export_attack_surface(
        self,
        attack_surface: AttackSurfaceMap,
        output_path: str | Path,
    ) -> None:
        """Write attack surface map to a JSON file."""
        Path(output_path).write_text(
            json.dumps(
                attack_surface.model_dump(mode="json"),
                indent=2,
                cls=JSONEncoder,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
