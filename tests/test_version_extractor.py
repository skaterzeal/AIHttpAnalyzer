import pytest

from src.core.models import HTTPResponse
from src.extractors.version_extractor import VersionExtractor


def make_response(body: str, headers: dict | None = None) -> HTTPResponse:
    return HTTPResponse(
        status_code=200,
        headers=headers or {},
        body=body,
        content_type="text/html",
        size_bytes=len(body.encode()),
        response_time_ms=None,
        request=None,
        source="test",
    )


def test_server_header_version():
    resp = make_response("", headers={"server": "Apache/2.4.51 (Ubuntu)"})
    findings = VersionExtractor().extract(resp)
    assert any("2.4.51" in f.detail for f in findings)


def test_xpoweredby_version():
    resp = make_response("", headers={"x-powered-by": "PHP/8.1.0"})
    findings = VersionExtractor().extract(resp)
    assert any("8.1.0" in f.detail for f in findings)
