from __future__ import annotations

from src.core.models import HTTPRequest, HTTPResponse


class RawHTTPParser:
    """Parse raw HTTP request/response text blocks."""

    def parse_response(
        self,
        response_raw: str,
        request_raw: str | None = None,
        url: str = "",
        source: str = "file",
    ) -> HTTPResponse:
        """Parse a raw HTTP response string into HTTPResponse model."""
        # Header / body ayır
        if "\r\n\r\n" in response_raw:
            header_block, body = response_raw.split("\r\n\r\n", 1)
        elif "\n\n" in response_raw:
            header_block, body = response_raw.split("\n\n", 1)
        else:
            header_block, body = response_raw, ""

        lines = header_block.splitlines()
        status_code = 0
        if lines:
            first = lines[0].strip()
            parts = first.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        request = None
        if request_raw:
            request = self._parse_request(request_raw, url)

        return HTTPResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            content_type=headers.get("content-type"),
            size_bytes=len(body.encode("utf-8", errors="ignore")),
            response_time_ms=None,
            request=request,
            source=source,
        )

    def _parse_request(self, request_raw: str, url: str) -> HTTPRequest | None:
        """Parse raw HTTP request text into HTTPRequest model."""
        if not request_raw.strip():
            return None

        lines = request_raw.splitlines()
        if not lines:
            return None

        first = lines[0].strip()
        parts = first.split()
        method = parts[0] if len(parts) > 0 else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        headers = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            line = lines[i]
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
            i += 1

        body = ""
        if i < len(lines):
            body = "\n".join(lines[i + 1 :])

        return HTTPRequest(
            method=method,
            url=url,
            path=path,
            headers=headers,
            body=body if body else None,
            timestamp=None,
        )
