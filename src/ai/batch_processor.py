from __future__ import annotations

import asyncio

from rich.progress import Progress

from src.core.models import AnalyzedResponse
from src.ai.response_analyzer import ResponseAnalyzer


class BatchProcessor:
    """Process multiple responses through AI in controlled batches."""

    def __init__(self, analyzer: ResponseAnalyzer, batch_size: int = 10):
        self.analyzer = analyzer
        self.batch_size = batch_size

    async def process_all(
        self,
        analyzed: list[AnalyzedResponse],
        question: str | None = None,
    ) -> list[AnalyzedResponse]:
        """
        Çok sayıda response'u batch'ler halinde AI ile analiz et.
        Rate limiting ve token limit aşımını engeller.
        """
        if not analyzed:
            return []

        batch_size = max(1, self.batch_size or 10)
        results = []

        with Progress() as progress:
            task = progress.add_task("AI analizi...", total=len(analyzed))
            
            for i in range(0, len(analyzed), batch_size):
                chunk = analyzed[i : i + batch_size]
                
                async def process_one(ar: AnalyzedResponse) -> AnalyzedResponse:
                    ar.ai_analysis = await self.analyzer.analyze(
                        response=ar.response,
                        pre_extracted=ar.findings,
                        question=question,
                    )
                    await asyncio.sleep(0.5)  # rate limiting
                    return ar
                
                chunk_results = await asyncio.gather(*(process_one(ar) for ar in chunk))
                results.extend(chunk_results)
                progress.advance(task, advance=len(chunk))

        return results
