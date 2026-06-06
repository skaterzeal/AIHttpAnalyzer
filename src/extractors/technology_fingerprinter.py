from __future__ import annotations

import re
from pathlib import Path

import yaml

from src.core.models import HTTPResponse


class TechnologyFingerprinter:
    """Fingerprint web technologies from HTTP response headers and body."""

    def __init__(self, fingerprints_path: str | None = None):
        if fingerprints_path is None:
            fingerprints_path = Path(__file__).resolve().parents[2] / "data" / "patterns" / "technology_fingerprints.yaml"
        with open(fingerprints_path, "r", encoding="utf-8") as f:
            self.fingerprints = yaml.safe_load(f)["fingerprints"]

    def detect(self, response: HTTPResponse) -> list[str]:
        """
        Response header ve body'den kullanılan teknoloji stack'ini tespit et.
        Döndür: ["Django", "PostgreSQL", "Nginx 1.24"] gibi liste.
        """
        detected = []

        for fp in self.fingerprints:
            score = 0
            total = 0

            # Header indikatörleri
            for ind in fp.get("indicators", {}).get("headers", []):
                total += 1
                val = response.headers.get(ind["name"].lower(), "")
                if "value" in ind and val.lower() == ind["value"].lower():
                    score += 1
                elif "pattern" in ind and re.search(ind["pattern"], val, re.I):
                    score += 1

            # Body indikatörleri
            for kw in fp.get("indicators", {}).get("body", []):
                total += 1
                if kw.lower() in response.body.lower():
                    score += 1

            # Eşleşme eşiği: indikatörlerin en az %40'ı
            if total > 0 and score / total >= 0.4:
                detected.append(fp["name"])

        return detected
