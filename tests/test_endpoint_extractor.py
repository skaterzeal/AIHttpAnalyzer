import pytest

from src.core.models import HTTPResponse
from src.extractors.endpoint_extractor import EndpointExtractor


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


def test_json_url_extracted():
    resp = make_response('{"endpoint": "/api/v2/users", "data": []}')
    found = EndpointExtractor().extract(resp)
    assert "/api/v2/users" in found


def test_html_form_action_extracted():
    resp = make_response('<form action="/admin/login" method="POST">')
    found = EndpointExtractor().extract(resp)
    assert "/admin/login" in found


def test_fetch_url_extracted():
    resp = make_response('fetch("/api/internal/config")')
    found = EndpointExtractor().extract(resp)
    assert "/api/internal/config" in found


def test_blocklist_filtered():
    resp = make_response('{"url": "/", "href": "//"}')
    found = EndpointExtractor().extract(resp)
    assert "/" not in found
    assert "//" not in found
