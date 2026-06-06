from __future__ import annotations

import base64
from pathlib import Path

from lxml import etree

from src.core.models import HTTPRequest, HTTPResponse


class BurpImporter:
    """Import HTTP responses from Burp Suite XML export files."""

    def parse(self, xml_path: str | Path) -> list[HTTPResponse]:
        """
        Burp Suite XML export dosyasını parse et.
        """
        tree = etree.parse(str(xml_path))
        items = tree.findall(".//item")
        responses = []

        for item in items:
            try:
                responses.append(self._parse_item(item))
            except Exception:
                continue  # parse edilemeyen item'ları atla

        return responses

    def _parse_item(self, item) -> HTTPResponse:
        # Request
        req_raw = item.findtext("request") or ""
        req_b64 = item.find("request")
        if req_b64 is not None and req_b64.get("base64") == "true":
            req_raw = base64.b64decode(req_raw).decode("utf-8", errors="ignore")

        # Response
        resp_raw = item.findtext("response") or ""
        resp_el = item.find("response")
        if resp_el is not None and resp_el.get("base64") == "true":
            resp_raw = base64.b64decode(resp_raw).decode("utf-8", errors="ignore")

        return self._parse_raw_http(
            request_raw=req_raw,
            response_raw=resp_raw,
            url=item.findtext("url") or "",
            status_code=int(item.findtext("status") or 0),
            source="burp",
        )

    def _parse_raw_http(
        self,
        request_raw: str,
        response_raw: str,
        url: str,
        status_code: int,
        source: str,
    ) -> HTTPResponse:
        """Ham HTTP metin bloğunu HTTPResponse modeline dönüştür."""
        # Header / body ayır
        if "\r\n\r\n" in response_raw:
            header_block, body = response_raw.split("\r\n\r\n", 1)
        elif "\n\n" in response_raw:
            header_block, body = response_raw.split("\n\n", 1)
        else:
            header_block, body = response_raw, ""

        # Header'ları parse et
        headers = {}
        for line in header_block.split("\n")[1:]:  # ilk satır status line
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        return HTTPResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            content_type=headers.get("content-type"),
            size_bytes=len(body.encode("utf-8", errors="ignore")),
            response_time_ms=None,
            request=self._parse_request(request_raw, url),
            source=source,
        )

    def _parse_request(self, request_raw: str, url: str) -> HTTPRequest | None:
        """Parse raw HTTP request text into HTTPRequest model."""
        if not request_raw.strip():
            return None

        lines = request_raw.splitlines()
        if not lines:
            return None

        # First line: METHOD PATH HTTP/1.1
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

        # Body starts after empty line
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
