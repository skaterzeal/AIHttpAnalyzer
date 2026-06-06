from __future__ import annotations

import pytest
from src.core.utils import normalize_body
from src.ai.smart_truncator import SmartTruncator
from src.core.models import ExtractedFinding, FindingType, Severity, HTTPResponse, HTTPRequest
from src.extractors.secret_extractor import SecretExtractor


def test_normalize_body():
    # Test UUID replacement
    body1 = "User ID: f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    assert "User ID: [UUID]" in normalize_body(body1)

    # Test timestamp replacement
    body2 = "Created at: 2026-06-06T00:28:39.123Z"
    assert "Created at: [TIMESTAMP]" in normalize_body(body2)

    # Test CSRF JSON replacement
    body3 = '{"csrf_token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"}'
    assert '"csrf_token": "[DYNAMIC_VALUE]"' in normalize_body(body3)

    # Test HTML input CSRF replacement
    body4 = '<input type="hidden" name="authenticity_token" value="xyz123abc456">'
    assert '<input type="hidden" name="authenticity_token" value="[DYNAMIC_VALUE]"' in normalize_body(body4)


def test_smart_truncator():
    truncator = SmartTruncator()
    # Large body with a finding
    body = "HTML Start\n" + "A" * 5000 + "\nSensitive data found here: SECRET_EXPOSED_123\n" + "B" * 5000 + "\nHTML End"
    findings = [
        ExtractedFinding(
            id="1",
            finding_type=FindingType.SECRET_EXPOSURE,
            severity=Severity.HIGH,
            title="Exposure",
            detail="Secret leaked",
            evidence="SECRET_EXPOSED_123",
            location="body",
            response_id="test",
            confidence=0.9
        )
    ]
    truncated = truncator.truncate(body, findings, max_length=4000)
    assert len(truncated) < len(body)
    assert "SECRET_EXPOSED_123" in truncated
    assert "HTML Start" in truncated
    assert "HTML End" in truncated
    assert "... [SNIP] ..." in truncated


def test_secret_extractor_filtering():
    extractor = SecretExtractor()
    
    # 1. Matches with false-positive placeholders should be skipped
    resp_false = HTTPResponse(
        status_code=200,
        headers={},
        body='{"password": "null", "api_key": "undefined"}',
        content_type="application/json",
        size_bytes=44,
        response_time_ms=0.0,
        request=None,
        source="test"
    )
    findings_false = extractor.extract(resp_false)
    assert len(findings_false) == 0

    # 2. Genuine high-entropy secrets should be detected
    resp_true = HTTPResponse(
        status_code=200,
        headers={},
        body='{"password": "MySuperSecretPassword123!", "api_key": "AbCdEfGhIjKlMnOpQrStUvWxYz"}',
        content_type="application/json",
        size_bytes=90,
        response_time_ms=0.0,
        request=None,
        source="test"
    )
    findings_true = extractor.extract(resp_true)
    assert len(findings_true) == 2


@pytest.mark.asyncio
async def test_robust_json_parsing():
    from src.ai.response_analyzer import ResponseAnalyzer
    analyzer = ResponseAnalyzer(provider="openai", model="gpt-4o-mini")
    
    raw_output = """Here is the JSON:
```json
{
  "summary": "This is a summary",
  "exploitable_findings": ["Finding 1"],
  "recommended_tests": ["Test 1"],
  "risk_level": "medium",
  "reasoning": "Reason",
  "hidden_endpoints": ["/endpoint"],
  "technologies_detected": ["Django"],
  "security_headers_missing": ["CSP"]
}
```
Hope that helps!"""
    resp = HTTPResponse(
        status_code=200, headers={}, body="", content_type="text/html",
        size_bytes=0, response_time_ms=None, request=None, source="test"
    )
    result = analyzer._parse(raw_output, resp)
    assert result.summary == "This is a summary"
    assert result.risk_level.value == "medium"
    assert "/endpoint" in result.hidden_endpoints
    assert "Django" in result.technologies_detected
    assert "CSP" in result.security_headers_missing


@pytest.mark.asyncio
async def test_batch_processor_chunking(tmp_path):
    class MockAnalyzer:
        def __init__(self):
            self.call_count = 0
        async def analyze(self, response, pre_extracted, question=None):
            self.call_count += 1
            from src.core.models import AIAnalysisResult, Severity
            return AIAnalysisResult(
                response_id="",
                summary="mock",
                exploitable_findings=[],
                recommended_tests=[],
                risk_level=Severity.INFO,
                reasoning="mock",
                raw_llm_output="{}"
            )
            
    from src.ai.batch_processor import BatchProcessor
    mock_analyzer = MockAnalyzer()
    processor = BatchProcessor(mock_analyzer, batch_size=2)
    
    from src.core.models import AnalyzedResponse
    from datetime import datetime, timezone
    
    analyzed_list = []
    for i in range(5):
        resp = HTTPResponse(
            status_code=200, headers={}, body=f"body_{i}", content_type="text/html",
            size_bytes=6, response_time_ms=None, request=None, source="test"
        )
        ar = AnalyzedResponse(
            response_id=f"id_{i}",
            response=resp,
            findings=[],
            ai_analysis=None,
            endpoints_found=[],
            technologies=[],
            analyzed_at=datetime.now(timezone.utc)
        )
        analyzed_list.append(ar)
        
    results = await processor.process_all(analyzed_list)
    assert len(results) == 5
    assert mock_analyzer.call_count == 5
    for r in results:
        assert r.ai_analysis is not None
        assert r.ai_analysis.summary == "mock"


@pytest.mark.asyncio
async def test_sqlite_wal_mode(tmp_path):
    from src.output.sqlite_store import SQLiteStore
    import aiosqlite
    db_file = tmp_path / "test_wal.db"
    store = SQLiteStore(str(db_file))
    await store.init_db()
    
    async with aiosqlite.connect(str(db_file)) as db:
        async with db.execute("PRAGMA journal_mode") as cursor:
            row = await cursor.fetchone()
            assert row[0].lower() == "wal"


@pytest.mark.asyncio
async def test_proxy_listener_logging():
    from src.ingestion.proxy_listener import ResponseCapture
    from src.core.engine import HTTPResponseAnalyzerEngine
    from src.core.config import Config
    
    cfg = Config()
    engine = HTTPResponseAnalyzerEngine(cfg)
    capture = ResponseCapture(engine, ai_enabled=False)
    
    assert capture.console is not None
