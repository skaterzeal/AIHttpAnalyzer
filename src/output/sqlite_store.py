from __future__ import annotations

import json
import aiosqlite
from pathlib import Path
from datetime import datetime

from src.core.models import (
    AnalyzedResponse,
    AttackSurfaceMap,
    ExtractedFinding,
    AIAnalysisResult,
    Severity,
    HTTPResponse,
)


class SQLiteStore:
    """Persist analysis results to a SQLite database."""

    def __init__(self, db_path: str = "analyzer.db"):
        self.db_path = db_path

    async def init_db(self):
        """Initialize the SQLite schema."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS analyzed_responses (
                    id TEXT PRIMARY KEY,
                    url TEXT,
                    status_code INTEGER,
                    source TEXT,
                    findings_json TEXT,
                    ai_analysis_json TEXT,
                    endpoints_json TEXT,
                    technologies_json TEXT,
                    analyzed_at TEXT,
                    response_hash TEXT
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_surface_maps (
                    target TEXT PRIMARY KEY,
                    total_responses INTEGER,
                    unique_endpoints_json TEXT,
                    technologies_json TEXT,
                    critical_findings_json TEXT,
                    ai_summary TEXT,
                    generated_at TEXT
                )
                """
            )
            await db.commit()

            # Migration: Add response_hash column if it doesn't exist
            try:
                await db.execute(
                    "ALTER TABLE analyzed_responses ADD COLUMN response_hash TEXT"
                )
                await db.commit()
            except Exception:
                pass

    async def save(self, result: AnalyzedResponse) -> None:
        """Save a single AnalyzedResponse to the database."""
        await self.init_db()
        url = result.response.request.url if result.response.request else ""
        import hashlib
        from src.core.utils import normalize_body
        normalized = normalize_body(result.response.body)
        response_hash = hashlib.sha256(
            normalized.encode("utf-8", errors="ignore")
        ).hexdigest()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO analyzed_responses
                (id, url, status_code, source, findings_json, ai_analysis_json,
                 endpoints_json, technologies_json, analyzed_at, response_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.response_id,
                    url,
                    result.response.status_code,
                    result.response.source,
                    json.dumps([f.model_dump(mode="json") for f in result.findings]),
                    json.dumps(result.ai_analysis.model_dump(mode="json"))
                    if result.ai_analysis
                    else None,
                    json.dumps(result.endpoints_found),
                    json.dumps(result.technologies),
                    result.analyzed_at.isoformat(),
                    response_hash,
                ),
            )
            await db.commit()

    async def save_attack_surface(self, asm: AttackSurfaceMap) -> None:
        """Save an AttackSurfaceMap to the database."""
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO attack_surface_maps
                (target, total_responses, unique_endpoints_json, technologies_json,
                 critical_findings_json, ai_summary, generated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    asm.target,
                    asm.total_responses,
                    json.dumps(asm.unique_endpoints),
                    json.dumps(asm.technologies),
                    json.dumps([f.model_dump(mode="json") for f in asm.critical_findings]),
                    asm.ai_summary,
                    asm.generated_at.isoformat(),
                ),
            )
            await db.commit()

    async def get_cached(
        self,
        response_hash: str,
        original_response: HTTPResponse,
    ) -> AnalyzedResponse | None:
        """Get cached AnalyzedResponse by response body hash if it exists."""
        await self.init_db()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT id, findings_json, ai_analysis_json, endpoints_json,
                       technologies_json, analyzed_at
                FROM analyzed_responses
                WHERE response_hash = ?
                ORDER BY analyzed_at DESC
                LIMIT 1
                """,
                (response_hash,),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None

                findings = []
                try:
                    findings_data = json.loads(row["findings_json"])
                    for f in findings_data:
                        findings.append(ExtractedFinding(**f))
                except Exception:
                    pass

                ai_analysis = None
                if row["ai_analysis_json"]:
                    try:
                        ai_data = json.loads(row["ai_analysis_json"])
                        ai_analysis = AIAnalysisResult(**ai_data)
                    except Exception:
                        pass

                endpoints = []
                if row["endpoints_json"]:
                    try:
                        endpoints = json.loads(row["endpoints_json"])
                    except Exception:
                        pass

                technologies = []
                if row["technologies_json"]:
                    try:
                        technologies = json.loads(row["technologies_json"])
                    except Exception:
                        pass

                analyzed_at = datetime.fromisoformat(row["analyzed_at"])

                return AnalyzedResponse(
                    response_id=row["id"],
                    response=original_response,
                    findings=findings,
                    ai_analysis=ai_analysis,
                    endpoints_found=endpoints,
                    technologies=technologies,
                    analyzed_at=analyzed_at,
                )
