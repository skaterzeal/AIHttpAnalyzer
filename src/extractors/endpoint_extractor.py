from __future__ import annotations

import re

from src.core.models import HTTPResponse


class EndpointExtractor:
    """Extract API endpoints, paths, and URLs from HTTP responses."""

    # API endpoint kalıpları
    PATTERNS = [
        # JSON anahtarları: "url", "endpoint", "href", "action" vb.
        re.compile(
            r'"(?:url|endpoint|href|action|src|link|path|api_url|base_url)"\s*:\s*"(/[^"]{2,})"'
        ),
        # HTML form action'ları
        re.compile(r'action=["\']([^"\']+)["\']'),
        # HTML link'ler
        re.compile(r'href=["\'](/[a-zA-Z0-9/_\-?.=&%#]+)["\']'),
        # JS fetch/axios çağrıları
        re.compile(
            r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](/[^'"]+)"""
        ),
        # REST path'leri: /api/v1/... , /v2/... vb.
        re.compile(
            r'"(/(?:api|v\d+|rest|graphql|gql|rpc)/[a-zA-Z0-9/_\-?.=&%#]+)"'
        ),
        # Relative URL'ler (/users/123)
        re.compile(
            r'"(/[a-zA-Z][a-zA-Z0-9/_\-]{3,}(?:\.[a-zA-Z]{2,4})?)"'
        ),
    ]

    # Çok genel veya anlamsız path'leri filtrele
    BLOCKLIST = {
        "/",
        "//",
        "/.",
        "/*",
        "/null",
        "/undefined",
        "/true",
        "/false",
        "/0",
        "/1",
    }

    def extract(self, response: HTTPResponse) -> list[str]:
        """
        Response body ve Location headerından endpoint'leri çıkar.
        """
        found = set()
        body = response.body

        for pat in self.PATTERNS:
            for m in pat.finditer(body):
                path = m.group(1)
                if self._is_valid_path(path):
                    found.add(path)

        # Location header
        loc = response.headers.get("location", "")
        if loc.startswith("/"):
            found.add(loc)

        # Content-Location header
        cl = response.headers.get("content-location", "")
        if cl.startswith("/"):
            found.add(cl)

        return sorted(found)

    def _is_valid_path(self, path: str) -> bool:
        if path in self.BLOCKLIST:
            return False
        if len(path) < 2 or len(path) > 200:
            return False
        # Sadece path karakterleri içermeli
        if re.search(r'[<>{}|\\^`\[\]\s]', path):
            return False
        return True
