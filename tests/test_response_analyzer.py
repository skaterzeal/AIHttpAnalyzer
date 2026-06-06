import pytest

from src.core.models import HTTPResponse, HTTPRequest
from src.core.config import Config
from src.core.engine import HTTPResponseAnalyzerEngine


def make_response(body: str, headers: dict | None = None, url: str = "https://example.com/") -> HTTPResponse:
    return HTTPResponse(
        status_code=200,
        headers=headers or {},
        body=body,
        content_type="text/html",
        size_bytes=len(body.encode()),
        response_time_ms=None,
        request=HTTPRequest(method="GET", url=url, path="/", headers={}, body=None, timestamp=None),
        source="test",
    )


@pytest.mark.asyncio
async def test_analyze_single_finds_endpoints():
    cfg = Config()
    engine = HTTPResponseAnalyzerEngine(cfg)
    resp = make_response('{"url": "/api/v1/users"}')
    result = await engine.analyze_single(resp)
    assert "/api/v1/users" in result.endpoints_found


@pytest.mark.asyncio
async def test_analyze_single_finds_stack_trace():
    cfg = Config()
    engine = HTTPResponseAnalyzerEngine(cfg)
    body = "Traceback (most recent call last):\n  File \"/app/main.py\", line 1\nValueError: fail"
    resp = make_response(body)
    result = await engine.analyze_single(resp)
    assert any(f.finding_type.value == "stack_trace" for f in result.findings)


@pytest.mark.asyncio
async def test_analyze_single_finds_version():
    cfg = Config()
    engine = HTTPResponseAnalyzerEngine(cfg)
    resp = make_response("", headers={"server": "nginx/1.24.0"})
    result = await engine.analyze_single(resp)
    assert any(f.finding_type.value == "version_disclosure" for f in result.findings)
