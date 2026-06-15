"""Event source contract.

An EventSource is an async iterator of ExecEvent. Nothing more.
This is the seam where the audisp-vs-logparse decision lives — and where it
stays contained.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from ..config import Config
from ..events import ExecEvent


class EventSource(ABC):
    """Async source of normalized execution events."""

    def __init__(self, config: Config) -> None:
        self.config = config

    @abstractmethod
    def events(self) -> AsyncIterator[ExecEvent]:
        """Yield ExecEvent objects until cancelled. Must be an async generator."""
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release any open handles. Override if needed."""
        return None


def get_source(config: Config) -> EventSource:
    """Factory: instantiate the source named in config (daemon.source)."""
    name = config.get("daemon.source", "logparse")
    if name == "logparse":
        from .logparse import LogParseSource
        return LogParseSource(config)
    if name == "audisp":
        from .audisp import AudispSource  # noqa: F401 — not implemented in V0.1
        return AudispSource(config)
    raise ValueError(f"unknown daemon.source: {name!r}")
