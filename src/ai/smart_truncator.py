from __future__ import annotations

import re
from src.core.models import ExtractedFinding


class SmartTruncator:
    """
    HTTP response gövdesini LLM'e göndermek için akıllıca kırpar.
    Bulunan zafiyet/bilgi ifşası kanıtlarını (evidence) ve HTML formlarını korur,
    gereksiz CSS/JS/HTML şablonlarını temizler.
    """

    def truncate(
        self,
        body: str,
        findings: list[ExtractedFinding],
        max_length: int = 4000,
    ) -> str:
        if not body:
            return ""
        if len(body) <= max_length:
            return body

        # Segment listesi: her öge (start_idx, end_idx) biçimindedir
        segments = []

        # 1. İlk 500 ve son 500 karakteri her zaman ekle (JSON/HTML yapısı için)
        segments.append((0, min(500, len(body))))
        segments.append((max(0, len(body) - 500), len(body)))

        # 2. Bulguların (findings) kanıtlarının etrafındaki alanları yakala
        for f in findings:
            evidence = f.evidence
            if not evidence:
                continue
            # Body içinde ara
            start_pos = 0
            while True:
                idx = body.find(evidence, start_pos)
                if idx == -1:
                    break
                # 200 karakter öncesi ve sonrası
                start = max(0, idx - 200)
                end = min(len(body), idx + len(evidence) + 200)
                segments.append((start, end))
                # Bir sonraki eşleşmeyi ara
                start_pos = idx + len(evidence)
                if start_pos >= len(body):
                    break

        # 3. HTML formları, input alanları, script etiketleri ve relative api path'leri yakala
        interesting_patterns = [
            re.compile(r"<form[^>]*>", re.IGNORECASE),
            re.compile(r"<input[^>]*>", re.IGNORECASE),
            re.compile(r"<select[^>]*>", re.IGNORECASE),
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"(\b(?:api/v\d+|/api/|/v\d+/)[a-zA-Z0-9_\-./]+)", re.IGNORECASE),
        ]

        for pat in interesting_patterns:
            for m in pat.finditer(body):
                start = max(0, m.start() - 100)
                end = min(len(body), m.end() + 100)
                segments.append((start, end))

        # 4. Segmentleri birleştir ve sırala (çakışanları birleştir)
        segments.sort(key=lambda x: x[0])
        merged = []
        for seg in segments:
            if not merged:
                merged.append(seg)
            else:
                last = merged[-1]
                if seg[0] <= last[1]:  # Çakışıyor veya bitişik
                    merged[-1] = (last[0], max(last[1], seg[1]))
                else:
                    merged.append(seg)

        # 5. Segmentlerden metin parçalarını oluştur
        chunks = []
        total_len = 0
        for start, end in merged:
            chunk = body[start:end].strip()
            if chunk:
                chunks.append((start, chunk))
                total_len += len(chunk)

        # Eğer hala çok uzunsa, sadece bulguları ve ilk/son kısımları tutacak şekilde daralt
        if total_len > max_length:
            critical_segments = []
            critical_segments.append((0, min(500, len(body))))
            critical_segments.append((max(0, len(body) - 500), len(body)))

            for f in findings:
                evidence = f.evidence
                if not evidence:
                    continue
                idx = body.find(evidence)
                if idx != -1:
                    start = max(0, idx - 150)
                    end = min(len(body), idx + len(evidence) + 150)
                    critical_segments.append((start, end))

            critical_segments.sort(key=lambda x: x[0])
            merged_crit = []
            for seg in critical_segments:
                if not merged_crit:
                    merged_crit.append(seg)
                else:
                    last = merged_crit[-1]
                    if seg[0] <= last[1]:
                        merged_crit[-1] = (last[0], max(last[1], seg[1]))
                    else:
                        merged_crit.append(seg)

            chunks = []
            for start, end in merged_crit:
                chunks.append((start, body[start:end].strip()))

        # Metin parçalarını birleştirirken aralara [SNIP] koy
        final_parts = []
        last_pos = 0
        for start, chunk in chunks:
            if start > last_pos and last_pos > 0:
                final_parts.append("\n... [SNIP] ...\n")
            final_parts.append(chunk)
            last_pos = start + len(chunk)

        return "".join(final_parts)
