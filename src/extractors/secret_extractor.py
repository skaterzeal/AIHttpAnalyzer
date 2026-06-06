from __future__ import annotations

import re
import uuid

from src.core.models import HTTPResponse, ExtractedFinding, FindingType, Severity

import math

# Yaygın sır kalıpları — JS Secret Hunter'a kıyasla response'a özgü
SECRET_PATTERNS = {
    "api_key_json": re.compile(
        r'"(?:api_?key|apikey|access_?key)"\s*:\s*"([^"]{12,})"'
    ),
    "token_json": re.compile(
        r'"(?:token|access_token|auth_token)"\s*:\s*"([^"]{12,})"'
    ),
    "password_json": re.compile(
        r'"(?:password|passwd|pwd|secret)"\s*:\s*"([^"]{6,})"'
    ),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "jwt": re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"
    ),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"
    ),
    "db_url": re.compile(
        r"(?:mysql|postgresql|mongodb|redis)://[^\s'\"<>]+"
    ),
    "internal_ip": re.compile(
        r"(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+"
    ),
    "email_internal": re.compile(
        r"[a-zA-Z0-9._%+-]+@(?:internal|corp|local|intranet)\.[a-zA-Z]+"
    ),
}

SECRET_BLOCKLIST = {
    "null", "false", "true", "none", "undefined", "password", "secret",
    "admin", "default", "changeit", "qwerty", "test", "testing", "welcome",
    "123456", "12345678", "123456789", "12345", "password123", "secret123"
}


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon Entropy of a string to measure its randomness."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy


class SecretExtractor:
    """Extract secrets and sensitive data from HTTP responses."""

    def extract(self, response: HTTPResponse) -> list[ExtractedFinding]:
        """Scan response body for exposed secrets."""
        findings = []
        body = response.body

        for name, pat in SECRET_PATTERNS.items():
            for m in pat.finditer(body):
                value = m.group(1) if m.lastindex else m.group(0)
                val_lower = value.lower().strip()

                # 1. Hariç tutma listesi kontrolü
                if val_lower in SECRET_BLOCKLIST:
                    continue

                # 2. Değerin uzunluk filtresi
                if len(value) < 6:
                    continue

                # 3. Entropi ve kalite kontrolleri
                entropy = shannon_entropy(value)

                # API key ve tokenlar için yüksek entropi aranır
                if name in ["api_key_json", "token_json", "jwt"]:
                    if len(value) < 12:
                        continue
                    if entropy < 2.5:  # Tekrarlayan veya çok basit karakterler
                        continue
                elif name == "password_json":
                    # Parola alanı için çok basit tekrarlayan karakterleri ele (örn. "aaaaaa", "123456")
                    if len(set(value)) <= 2:
                        continue
                    if entropy < 1.8:
                        continue

                findings.append(
                    ExtractedFinding(
                        id=str(uuid.uuid4()),
                        finding_type=FindingType.SECRET_EXPOSURE,
                        severity=Severity.HIGH,
                        title=f"Response İçinde Sır: {name}",
                        detail=f"Response body'de {name} deseni bulundu (Entropy: {entropy:.2f})",
                        evidence=value[:4] + "***" + value[-4:] if len(value) > 8 else value,
                        location=f"body (offset {m.start()})",
                        response_id="",
                        confidence=0.80,
                    )
                )

        return findings
