"""audisp event source — DEFERRED.

The architecture decision (audisp plugin vs. log-parsing) is intentionally not
nailed down for V0.1. Per the design doc: prototype with log-parsing first;
sometimes parsing audit.log is 10x simpler than an audisp plugin. Decide after
the log-parsing prototype proves the event shape.

When implemented, an audisp plugin (registered in /etc/audit/plugins.d/) pushes
newline-delimited audit records to this process's stdin. This source would then
read stdin asynchronously and feed the same _assemble() logic as logparse.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from ..events import ExecEvent
from .base import EventSource


class AudispSource(EventSource):
    def events(self) -> AsyncIterator[ExecEvent]:  # pragma: no cover
        raise NotImplementedError(
            "audisp source not implemented in V0.1 — use daemon.source: logparse"
        )
