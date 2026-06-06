import pytest

from src.core.models import HTTPResponse, FindingType, Severity
from src.extractors.stack_trace_extractor import StackTraceExtractor


DJANGO_TRACE = """
Traceback (most recent call last):
  File "/home/app/views.py", line 42, in get
    result = User.objects.get(id=user_id)
django.core.exceptions.ObjectDoesNotExist: User matching query does not exist.
"""


def make_response(body: str, headers: dict | None = None) -> HTTPResponse:
    return HTTPResponse(
        status_code=500,
        headers=headers or {},
        body=body,
        content_type="text/html",
        size_bytes=len(body.encode()),
        response_time_ms=None,
        request=None,
        source="test",
    )


def test_python_traceback_detected():
    resp = make_response(DJANGO_TRACE)
    findings = StackTraceExtractor().extract(resp)
    assert len(findings) > 0
    assert findings[0].finding_type == FindingType.STACK_TRACE
    assert findings[0].severity == Severity.HIGH


def test_file_path_extracted():
    resp = make_response(DJANGO_TRACE)
    findings = StackTraceExtractor().extract(resp)
    assert any("/home/app/views.py" in f.detail for f in findings)
