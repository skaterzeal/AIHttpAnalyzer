from __future__ import annotations

import re


def normalize_body(body: str) -> str:
    """
    HTTP response gövdesindeki dinamik alanları (zaman damgası, token, UUID vb.)
    temizleyerek/maskeleyerek önbellek (caching) isabet oranını artırır.
    """
    if not body:
        return ""

    # 1. ISO 8601 & HTTP Tarih damgaları
    # Örn: 2026-06-06T00:28:39+03:00 veya 2026-06-06T00:28:39.123Z
    body = re.sub(
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        "[TIMESTAMP]",
        body,
    )
    # Örn: 2026-06-06
    body = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "[DATE]", body)
    # Örn: Sat, 06 Jun 2026 00:28:39 GMT
    body = re.sub(
        r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT\b",
        "[TIMESTAMP]",
        body,
    )

    # 2. UUID'ler
    body = re.sub(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        "[UUID]",
        body,
    )

    # 3. Epoch Zaman Damgaları (10 veya 13 haneli sayılar)
    body = re.sub(r"\b\d{10}(?:\d{3})?\b", "[EPOCH_TIMESTAMP]", body)

    # 4. JWT Token'ları
    body = re.sub(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b",
        "[JWT_TOKEN]",
        body,
    )

    # 5. JSON Dinamik Değerleri (CSRF, token, session_id, vb.)
    # JSON içinde "csrf": "abc..." veya "session_id": "abc..." durumlarını yakalar
    body = re.sub(
        r'(")((?:csrf|xsrf|session|auth|token|state|nonce|key)(?:_token|_id|_key|_value)?)("\s*:\s*")[A-Za-z0-9+/=_-]{16,}(")',
        r"\1\2\3[DYNAMIC_VALUE]\4",
        body,
        flags=re.IGNORECASE,
    )

    # 6. HTML CSRF Hidden Input'ları
    # <input type="hidden" name="csrf" value="abc...">
    body = re.sub(
        r'(<input[^>]+name="[^"]*(?:csrf|xsrf|authenticity_token)[^"]*"[^>]+value=")[^"]+(")',
        r"\1[DYNAMIC_VALUE]\2",
        body,
        flags=re.IGNORECASE,
    )
    body = re.sub(
        r'(<input[^>]+value=")[^"]+("[^>]+name="[^"]*(?:csrf|xsrf|authenticity_token)[^"]*")',
        r"\1[DYNAMIC_VALUE]\2",
        body,
        flags=re.IGNORECASE,
    )

    return body
