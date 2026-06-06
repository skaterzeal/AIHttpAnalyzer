from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options

from src.core.models import HTTPRequest, HTTPResponse

if TYPE_CHECKING:
    from src.core.engine import HTTPResponseAnalyzerEngine


class ResponseCapture:
    """mitmproxy addon that captures and analyzes HTTP responses in real-time."""

    def __init__(self, engine: HTTPResponseAnalyzerEngine, ai_enabled: bool = False):
        self.engine = engine
        self.ai_enabled = ai_enabled
        self.queue: asyncio.Queue = asyncio.Queue()
        from rich.console import Console
        self.console = Console()

    def response(self, flow: http.HTTPFlow):
        """mitmproxy her response aldığında bu method çağrılır."""
        # Filter by content type
        content_type = flow.response.headers.get("content-type", "")
        allowed = [
            "application/json",
            "text/html",
            "text/plain",
            "application/xml",
        ]
        if not any(ct in content_type for ct in allowed):
            return

        resp = HTTPResponse(
            status_code=flow.response.status_code,
            headers=dict(flow.response.headers),
            body=flow.response.text or "",
            content_type=content_type,
            size_bytes=len(flow.response.content),
            response_time_ms=None,
            request=HTTPRequest(
                method=flow.request.method,
                url=flow.request.pretty_url,
                path=flow.request.path,
                headers=dict(flow.request.headers),
                body=flow.request.text,
                timestamp=None,
            ),
            source="proxy",
        )
        asyncio.create_task(self._analyze_and_annotate(flow, resp))

    async def _analyze_and_annotate(self, flow: http.HTTPFlow, resp: HTTPResponse):
        url = resp.request.url if resp.request else "N/A"
        method = resp.request.method if resp.request else "GET"
        self.console.print(f"[dim][*] Analiz ediliyor: {method} {url}[/dim]")
        
        result = await self.engine.analyze_single(resp)
        # Burp benzeri notasyon: bulgu varsa flow'u işaretle
        if result.findings:
            severity_counts = {}
            for f in result.findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            flow.comment = f"[AI Analyzer] {len(result.findings)} finding: {severity_counts}"
            
            # Print findings details to terminal
            self.console.print(f"\n[bold yellow][!] Yeni Bulgu Tespit Edildi ({url}):[/bold yellow]")
            for f in result.findings:
                color = "red" if f.severity in ["critical", "high"] else "yellow" if f.severity == "medium" else "green"
                self.console.print(f"  - [{color}]{f.severity.upper()}[/{color}] {f.title}: {f.detail}")
            self.console.print("")
        else:
            self.console.print(f"[green][+] Temiz: {method} {url}[/green]")


async def start_proxy(
    engine: HTTPResponseAnalyzerEngine,
    port: int = 8082,
    ai_enabled: bool = False,
):
    """Start mitmproxy with the ResponseCapture addon."""
    opts = options.Options(listen_host="127.0.0.1", listen_port=port)
    m = DumpMaster(opts)
    capture = ResponseCapture(engine, ai_enabled=ai_enabled)
    m.addons.add(capture)
    await m.run()
