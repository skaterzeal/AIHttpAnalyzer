from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Force UTF-8 on Windows terminals
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from src.core.config import Config
from src.core.engine import HTTPResponseAnalyzerEngine
from src.core.models import Severity, HTTPResponse, HTTPRequest
from src.ingestion.file_loader import FileLoader
from src.ingestion.raw_http_parser import RawHTTPParser
from src.output.json_exporter import JSONExporter
from src.output.markdown_reporter import MarkdownReporter
from src.output.sarif_exporter import SARIFExporter
from src.output.sqlite_store import SQLiteStore
from src.output.burp_annotation import annotate_burp_xml

app = typer.Typer(help="AI-Destekli HTTP Response Analyzer")
console = Console()


def _load_config(config_path: Optional[str]) -> Config:
    if config_path and Path(config_path).exists():
        return Config.from_yaml(config_path)
    default = Path("configs/default.yaml")
    if default.exists():
        return Config.from_yaml(default)
    return Config()


def _filter_by_severity(
    results: list, min_severity: Severity
) -> list:
    severity_order = [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    min_idx = severity_order.index(min_severity)
    allowed = severity_order[min_idx:]
    for r in results:
        r.findings = [f for f in r.findings if f.severity in allowed]
    return results


def _print_summary(results: list):
    counts = {s: 0 for s in Severity}
    endpoints = set()
    techs = set()
    for ar in results:
        for f in ar.findings:
            counts[f.severity] += 1
        endpoints.update(ar.endpoints_found)
        techs.update(ar.technologies)

    table = Table(title="Sonuçlar")
    table.add_column("Seviye", style="bold")
    table.add_column("Sayı")
    for sev, color, marker in [
        (Severity.CRITICAL, "red", "CRIT"),
        (Severity.HIGH, "orange3", "HIGH"),
        (Severity.MEDIUM, "yellow", "MED"),
        (Severity.LOW, "green", "LOW"),
        (Severity.INFO, "dim", "INFO"),
    ]:
        table.add_row(f"[{color}]{marker}[/{color}] {sev.value.upper()}", str(counts[sev]))

    console.print(table)
    console.print(f"\n[bold]Teknoloji stack:[/bold] {', '.join(sorted(techs)) or '—'}")
    console.print(f"[bold]Keşfedilen path:[/bold] {len(endpoints)}")


@app.command()
def analyze(
    file: Optional[str] = typer.Option(None, "--file", help="Tek .http dosyası"),
    burp: Optional[str] = typer.Option(None, "--burp", help="Burp Suite XML export"),
    dir: Optional[str] = typer.Option(None, "--dir", help="Dizindeki tüm .http dosyaları"),
    ai: bool = typer.Option(False, "--ai", help="AI analizini etkinleştir"),
    llm_provider: str = typer.Option("ollama", "--llm-provider", help="ollama / openai / anthropic"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="LLM API anahtarı"),
    min_severity: str = typer.Option("low", "--min-severity", help="info/low/medium/high/critical"),
    output: str = typer.Option("json", "--output", help="json/markdown/sarif/burp"),
    output_file: Optional[str] = typer.Option(None, "--output-file", help="Çıktı dosyası"),
    verbose: bool = typer.Option(False, "--verbose", help="Ayrıntılı log"),
    config: Optional[str] = typer.Option(None, "--config", help="Özel config"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Cache devre dışı"),
    batch_size: Optional[int] = typer.Option(None, "--batch-size", help="AI toplu işlem boyutu"),
):
    """HTTP response'larını analiz et."""
    cfg = _load_config(config)
    if ai:
        cfg.ai.enabled = True
        cfg.ai.provider = llm_provider
    if api_key:
        cfg.ai.enabled = True
        cfg.ai.provider = llm_provider
        cfg.ai.api_key = api_key
    if no_cache:
        cfg.cache.enabled = False
    if batch_size is not None:
        cfg.ai.batch_size = batch_size

    engine = HTTPResponseAnalyzerEngine(cfg)

    async def _run():
        results = []
        source = ""
        if file:
            source = f"file: {file}"
            resp = FileLoader().load_file(file)
            results = [await engine.analyze_single(resp)]
        elif burp:
            source = f"burp: {burp}"
            results = await engine.analyze_burp_export(burp)
        elif dir:
            source = f"dir: {dir}"
            results = await engine.analyze_directory(dir)
        else:
            console.print("[red]Bir kaynak belirtmelisin: --file, --burp veya --dir[/red]")
            raise typer.Exit(1)

        results = _filter_by_severity(results, Severity(min_severity))

        console.print(
            Panel(
                f"Kaynak : {source} ({len(results)} response)\n"
                f"Mod    : {'full + AI' if ai else 'deterministic'}",
                title="AI HTTP Response Analyzer",
            )
        )
        _print_summary(results)

        # Output
        if output_file:
            if output == "json":
                JSONExporter().export(results, output_file)
            elif output == "markdown":
                MarkdownReporter().report(results, output_file)
            elif output == "sarif":
                SARIFExporter().export(results, output_file)
            elif output == "burp" and burp:
                annotate_burp_xml(burp, results, output_file)
            console.print(f"[green]Çıktı kaydedildi:[/green] {output_file}")

        # SQLite store
        for r in results:
            await engine.store.save(r)

    asyncio.run(_run())


@app.command()
def proxy(
    port: int = typer.Option(8082, "--port", help="Proxy dinleme portu"),
    ai: bool = typer.Option(False, "--ai", help="AI analizini etkinleştir"),
    llm_provider: str = typer.Option("ollama", "--llm-provider"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    config: Optional[str] = typer.Option(None, "--config"),
):
    """Canlı proxy modu (mitmproxy entegrasyonu)."""
    cfg = _load_config(config)
    if ai:
        cfg.ai.enabled = True
        cfg.ai.provider = llm_provider
    if api_key:
        cfg.ai.enabled = True
        cfg.ai.provider = llm_provider
        cfg.ai.api_key = api_key

    engine = HTTPResponseAnalyzerEngine(cfg)

    async def _run():
        from src.ingestion.proxy_listener import start_proxy

        console.print(f"[green]Proxy başlatıldı: 127.0.0.1:{port}[/green]")
        await start_proxy(engine, port=port, ai_enabled=ai)

    asyncio.run(_run())


@app.command()
def request(
    url: str = typer.Option(..., "--url", help="Doğrudan istek URL'i"),
    method: str = typer.Option("GET", "--method", help="HTTP metodu"),
    header: Optional[list[str]] = typer.Option(None, "--header", help="Ekstra headerlar"),
    ai: bool = typer.Option(False, "--ai", help="AI analizini etkinleştir"),
    llm_provider: str = typer.Option("ollama", "--llm-provider"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    min_severity: str = typer.Option("low", "--min-severity"),
    output_file: Optional[str] = typer.Option(None, "--output-file"),
    config: Optional[str] = typer.Option(None, "--config"),
):
    """URL'e istek at ve yanıtı analiz et."""
    cfg = _load_config(config)
    if ai:
        cfg.ai.enabled = True
        cfg.ai.provider = llm_provider
    if api_key:
        cfg.ai.enabled = True
        cfg.ai.provider = llm_provider
        cfg.ai.api_key = api_key

    engine = HTTPResponseAnalyzerEngine(cfg)

    async def _run():
        headers_dict = {}
        if header:
            for h in header:
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers_dict[k.strip()] = v.strip()

        async with httpx.AsyncClient() as client:
            resp = await client.request(method, url, headers=headers_dict)

        http_resp = HTTPResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text,
            content_type=resp.headers.get("content-type"),
            size_bytes=len(resp.content),
            response_time_ms=resp.elapsed.total_seconds() * 1000,
            request=HTTPRequest(
                method=method,
                url=url,
                path=resp.request.url.path,
                headers=headers_dict,
                body=None,
                timestamp=None,
            ),
            source="direct",
        )

        result = await engine.analyze_single(http_resp)
        if result.findings:
            console.print(f"[yellow]{len(result.findings)} bulgu tespit edildi.[/yellow]")
            for f in result.findings:
                console.print(f"- [{f.severity.value}] {f.title}")
        else:
            console.print("[green]Bulgu tespit edilmedi.[/green]")

        if output_file:
            JSONExporter().export([result], output_file)
            console.print(f"[green]Kaydedildi:[/green] {output_file}")

    asyncio.run(_run())


@app.command()
def ask(
    file: str = typer.Option(..., "--file", help="HTTP response dosyası"),
    question: str = typer.Option(..., "--question", help="AI'a özel soru"),
    llm_provider: str = typer.Option("ollama", "--llm-provider"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    config: Optional[str] = typer.Option(None, "--config"),
):
    """AI sorgulama modu — belirli bir soruyu yanıtla."""
    cfg = _load_config(config)
    cfg.ai.enabled = True
    cfg.ai.provider = llm_provider
    if api_key:
        cfg.ai.api_key = api_key

    engine = HTTPResponseAnalyzerEngine(cfg)

    async def _run():
        resp = FileLoader().load_file(file)
        result = await engine.analyze_single(resp, question=question)
        if result.ai_analysis:
            console.print(Panel(result.ai_analysis.summary, title="AI Özeti"))
            console.print(f"[bold]Risk:[/bold] {result.ai_analysis.risk_level.value}")
            if result.ai_analysis.recommended_tests:
                console.print("[bold]Öneriler:[/bold]")
                for t in result.ai_analysis.recommended_tests:
                    console.print(f"- {t}")
        else:
            console.print("[red]AI analizi başarısız.[/red]")

    asyncio.run(_run())


@app.command()
def map(
    burp: Optional[str] = typer.Option(None, "--burp", help="Burp Suite XML export"),
    dir: Optional[str] = typer.Option(None, "--dir", help="Dizin"),
    output: str = typer.Option("attack_surface.md", "--output", help="Çıktı dosyası"),
    ai: bool = typer.Option(False, "--ai", help="AI analizini etkinleştir"),
    llm_provider: str = typer.Option("ollama", "--llm-provider"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    config: Optional[str] = typer.Option(None, "--config"),
):
    """Tüm response'ları birleştirip saldırı yüzeyi haritası çıkar."""
    cfg = _load_config(config)
    if ai:
        cfg.ai.enabled = True
        cfg.ai.provider = llm_provider
    if api_key:
        cfg.ai.enabled = True
        cfg.ai.provider = llm_provider
        cfg.ai.api_key = api_key

    engine = HTTPResponseAnalyzerEngine(cfg)

    async def _run():
        if burp:
            results = await engine.analyze_burp_export(burp)
        elif dir:
            results = await engine.analyze_directory(dir)
        else:
            console.print("[red]--burp veya --dir belirtmelisin.[/red]")
            raise typer.Exit(1)

        asm = await engine.build_attack_surface(results)
        MarkdownReporter().report_attack_surface(asm, output)
        console.print(f"[green]Saldırı yüzeyi haritası kaydedildi:[/green] {output}")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
