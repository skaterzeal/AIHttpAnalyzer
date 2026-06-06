from __future__ import annotations

import asyncio
from aiohttp import web

from src.core.config import Config
from src.core.engine import HTTPResponseAnalyzerEngine
from src.core.models import HTTPResponse


async def analyze_endpoint(request: web.Request) -> web.Response:
    """Analyze a single HTTP response via POST JSON."""
    data = await request.json()
    engine: HTTPResponseAnalyzerEngine = request.app["engine"]
    resp = HTTPResponse(**data)
    result = await engine.analyze_single(resp)
    return web.json_response(result.model_dump(mode="json"))


async def health(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({"status": "ok"})


def create_app(config: Config | None = None) -> web.Application:
    """Create the aiohttp application for the local API server."""
    if config is None:
        config = Config()
    engine = HTTPResponseAnalyzerEngine(config)
    app = web.Application()
    app["engine"] = engine
    app.router.add_post("/analyze", analyze_endpoint)
    app.router.add_get("/health", health)
    return app


if __name__ == "__main__":
    app = create_app()
    web.run_app(app, host="127.0.0.1", port=8765)
