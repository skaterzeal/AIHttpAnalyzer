import pytest
import shutil
import asyncio
from pathlib import Path
from datetime import datetime, timedelta, timezone

from src.core.config import Config
from src.core.models import HTTPResponse, HTTPRequest, ExtractedFinding, FindingType, Severity, AIAnalysisResult, AnalyzedResponse
from src.core.engine import HTTPResponseAnalyzerEngine
from src.correlation.attack_surface_mapper import AttackSurfaceMapper
from src.output.sqlite_store import SQLiteStore


def make_response(body: str, url: str = "https://example.com/api") -> HTTPResponse:
    return HTTPResponse(
        status_code=200,
        headers={"content-type": "application/json", "server": "nginx/1.24.0"},
        body=body,
        content_type="application/json",
        size_bytes=len(body.encode()),
        response_time_ms=10.0,
        request=HTTPRequest(
            method="GET",
            url=url,
            path="/api",
            headers={},
            body=None,
            timestamp=None,
        ),
        source="test",
    )


@pytest.mark.asyncio
async def test_sqlite_cache_flow(tmp_path):
    cfg = Config()
    cfg.cache.enabled = True
    cfg.cache.ttl_hours = 2

    engine = HTTPResponseAnalyzerEngine(cfg)
    test_db = tmp_path / "test_cache.db"
    engine.store.db_path = str(test_db)

    resp = make_response('{"status": "ok", "version": "1.0"}')

    # First analysis (Cache Miss)
    result1 = await engine.analyze_single(resp)
    assert result1.response_id is not None
    
    # Verify it got saved in the database
    cached_row = await engine.store.get_cached(
        response_hash=await get_body_hash(resp.body),
        original_response=resp
    )
    assert cached_row is not None
    assert cached_row.response_id == result1.response_id

    # Second analysis (Cache Hit)
    result2 = await engine.analyze_single(resp)
    # The IDs should be identical because it was loaded from cache
    assert result2.response_id == result1.response_id


@pytest.mark.asyncio
async def test_sqlite_cache_ttl_expiration(tmp_path):
    cfg = Config()
    cfg.cache.enabled = True
    cfg.cache.ttl_hours = 1  # 1 hour TTL

    engine = HTTPResponseAnalyzerEngine(cfg)
    test_db = tmp_path / "test_ttl.db"
    engine.store.db_path = str(test_db)

    resp = make_response('{"data": "expired_test"}')

    # Analyze and save
    result1 = await engine.analyze_single(resp)

    # Let's manually modify the database record analyzed_at timestamp to be 3 hours ago
    async with engine.store.connect() as db:
        three_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        await db.execute(
            "UPDATE analyzed_responses SET analyzed_at = ? WHERE id = ?",
            (three_hours_ago, result1.response_id)
        )
        await db.commit()

    # Analyze again
    result2 = await engine.analyze_single(resp)
    # Since it is expired, it should be a cache miss and get a new response_id
    assert result2.response_id != result1.response_id


@pytest.mark.asyncio
async def test_attack_surface_mapper_with_ai_endpoints():
    mapper = AttackSurfaceMapper()
    
    # Create mock AnalyzedResponse with AI results containing hidden endpoints and technologies
    resp = make_response('{}')
    ai_res = AIAnalysisResult(
        response_id="mock_id",
        summary="Test summary",
        exploitable_findings=["Finding"],
        recommended_tests=["Test"],
        risk_level=Severity.HIGH,
        reasoning="Reason",
        raw_llm_output="{}",
        hidden_endpoints=["/api/v1/internal", "/debug/console"],
        technologies_detected=["FastAPI", "MongoDB"],
        security_headers_missing=["CSP"]
    )
    
    ar = AnalyzedResponse(
        response_id="ar_id",
        response=resp,
        findings=[],
        ai_analysis=ai_res,
        endpoints_found=["/api/v1/users"],
        technologies=["Nginx"],
        analyzed_at=datetime.now(timezone.utc)
    )

    asm = mapper.build_map([ar])
    
    # Endpoints should include both deterministic (/api/v1/users) and AI-detected endpoints (/api/v1/internal, /debug/console)
    assert "/api/v1/users" in asm.unique_endpoints
    assert "/api/v1/internal" in asm.unique_endpoints
    assert "/debug/console" in asm.unique_endpoints
    
    # Technologies should include both Nginx and AI-detected FastAPI, MongoDB
    assert "Nginx" in asm.technologies
    assert "FastAPI" in asm.technologies
    assert "MongoDB" in asm.technologies


# Helper function to compute hash
async def get_body_hash(body: str) -> str:
    import hashlib
    from src.core.utils import normalize_body
    normalized = normalize_body(body)
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


# Helper property to connect to DB for test modifications
def db_connect(self):
    import aiosqlite
    return aiosqlite.connect(self.db_path)

SQLiteStore.connect = db_connect
