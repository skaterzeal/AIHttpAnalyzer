from __future__ import annotations

import asyncio
from pathlib import Path

from src.core.models import HTTPResponse
from src.ingestion.raw_http_parser import RawHTTPParser


class FileLoader:
    """Load HTTP response files from disk."""

    def __init__(self) -> None:
        self.parser = RawHTTPParser()

    def load_file(self, path: str | Path) -> HTTPResponse:
        """Load a single .http file."""
        raw = Path(path).read_text(encoding="utf-8", errors="ignore")
        return self.parser.parse_response(raw, source="file")

    def load_directory(self, directory: str | Path) -> list[HTTPResponse]:
        """Load all .http files in a directory."""
        responses = []
        for fp in Path(directory).glob("*.http"):
            try:
                responses.append(self.load_file(fp))
            except Exception:
                continue
        return responses

    async def load_file_async(self, path: str | Path) -> HTTPResponse:
        """Async wrapper for load_file."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.load_file, path)

    async def load_directory_async(self, directory: str | Path) -> list[HTTPResponse]:
        """Async wrapper for load_directory."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.load_directory, directory)
