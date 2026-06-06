from __future__ import annotations

from src.core.models import HTTPResponse


class SessionTracker:
    """Track sessions and state across multiple HTTP responses."""

    def __init__(self):
        self.sessions: dict[str, list[HTTPResponse]] = {}

    def track(self, response: HTTPResponse) -> None:
        """Track a response under its host/session key."""
        host = response.request.url if response.request else "unknown"
        self.sessions.setdefault(host, []).append(response)

    def get_session(self, host: str) -> list[HTTPResponse]:
        """Get all tracked responses for a host."""
        return self.sessions.get(host, [])
