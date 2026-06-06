from __future__ import annotations

import uuid
from datetime import datetime, timezone

from rich.progress import Progress

from src.core.config import Config
from src.core.models import HTTPResponse, AnalyzedResponse, AttackSurfaceMap
from src.ingestion.burp_importer import BurpImporter
from src.ingestion.file_loader import FileLoader
from src.extractors.endpoint_extractor import EndpointExtractor
from src.extractors.stack_trace_extractor import StackTraceExtractor
from src.extractors.version_extractor import VersionExtractor
from src.extractors.secret_extractor import SecretExtractor
from src.extractors.error_extractor import ErrorExtractor
from src.extractors.technology_fingerprinter import TechnologyFingerprinter
from src.ai.response_analyzer import ResponseAnalyzer
from src.ai.batch_processor import BatchProcessor
from src.correlation.attack_surface_mapper import AttackSurfaceMapper
from src.output.sqlite_store import SQLiteStore


class HTTPResponseAnalyzerEngine:
    """Main orchestrator for HTTP response analysis."""

    def __init__(self, config: Config):
        self.config = config
        self.burp = BurpImporter()
        self.file_loader = FileLoader()
        self.ep_extractor = EndpointExtractor()
        self.st_extractor = StackTraceExtractor()
        self.ver_extractor = VersionExtractor()
        self.sec_extractor = SecretExtractor()
        self.err_extractor = ErrorExtractor()
        self.fingerprinter = TechnologyFingerprinter()
        self.ai_analyzer = None
        if config.ai.enabled:
            self.ai_analyzer = ResponseAnalyzer(
                provider=config.ai.provider,
                model=config.ai.model,
                api_key=config.ai.api_key,
            )
        self.batch = BatchProcessor(
            self.ai_analyzer, config.ai.batch_size
        ) if self.ai_analyzer else None
        self.correlator = AttackSurfaceMapper()
        self.store = SQLiteStore()

    async def analyze_single(
        self,
        response: HTTPResponse,
        question: str | None = None,
    ) -> AnalyzedResponse:
        """Tek bir HTTP response'u analiz et."""
        import hashlib
        from datetime import datetime, timezone
        from src.core.utils import normalize_body

        normalized = normalize_body(response.body)
        response_hash = hashlib.sha256(
            normalized.encode("utf-8", errors="ignore")
        ).hexdigest()

        if self.config.cache.enabled:
            cached = await self.store.get_cached(response_hash, response)
            if cached:
                # Check TTL
                now = datetime.now(timezone.utc)
                diff = now - cached.analyzed_at.replace(tzinfo=timezone.utc)
                age_hours = diff.total_seconds() / 3600.0
                if age_hours < self.config.cache.ttl_hours:
                    return cached

        # 1. Deterministic extractors — hepsi çalışır
        findings = []
        if self.config.analysis.extract_stack_traces:
            findings += self.st_extractor.extract(response)
        if self.config.analysis.extract_versions:
            findings += self.ver_extractor.extract(response)
        if self.config.analysis.extract_secrets:
            findings += self.sec_extractor.extract(response)
        if self.config.analysis.extract_errors:
            findings += self.err_extractor.extract(response)

        endpoints = []
        if self.config.analysis.extract_endpoints:
            endpoints = self.ep_extractor.extract(response)

        technologies = []
        if self.config.analysis.fingerprint_technology:
            technologies = self.fingerprinter.detect(response)

        # 2. AI analizi (etkinse)
        ai_result = None
        if self.ai_analyzer:
            ai_result = await self.ai_analyzer.analyze(
                response, findings, question
            )

        result = AnalyzedResponse(
            response_id=str(uuid.uuid4()),
            response=response,
            findings=findings,
            ai_analysis=ai_result,
            endpoints_found=endpoints,
            technologies=technologies,
            analyzed_at=datetime.now(timezone.utc),
        )

        if self.config.cache.enabled:
            await self.store.save(result)

        return result

    async def analyze_burp_export(
        self,
        xml_path: str,
        question: str | None = None,
    ) -> list[AnalyzedResponse]:
        """Burp XML export dosyasındaki tüm response'ları analiz et."""
        responses = self.burp.parse(xml_path)
        analyzed = []

        with Progress() as progress:
            task = progress.add_task(
                "Deterministic analiz...", total=len(responses)
            )
            for resp in responses:
                ar = await self.analyze_single(resp)
                analyzed.append(ar)
                progress.advance(task)

        # AI batch işlemi
        if self.batch:
            analyzed = await self.batch.process_all(analyzed, question)

        return analyzed

    async def analyze_directory(
        self,
        dir_path: str,
        question: str | None = None,
    ) -> list[AnalyzedResponse]:
        """Analyze all .http files in a directory."""
        responses = self.file_loader.load_directory(dir_path)
        analyzed = []

        with Progress() as progress:
            task = progress.add_task(
                "Deterministic analiz...", total=len(responses)
            )
            for resp in responses:
                ar = await self.analyze_single(resp)
                analyzed.append(ar)
                progress.advance(task)

        if self.batch:
            analyzed = await self.batch.process_all(analyzed, question)

        return analyzed

    async def build_attack_surface(
        self, analyzed: list[AnalyzedResponse]
    ) -> AttackSurfaceMap:
        """Build an attack surface map from analyzed responses."""
        return self.correlator.build_map(analyzed)
