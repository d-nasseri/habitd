"""Log-parsing event source — the prototype-first path.

Tails /var/log/audit/audit.log and assembles ExecEvent objects.

Verified against real Debian 12 / auditd 3.0.9 output (Qubes OS dev qube).

Record structure per event (all share the same audit id):
    type=SYSCALL   ... ppid=N pid=N uid=N exe="..." comm="..." key="habitd_exec"
    type=EXECVE    ... argc=N a0="..." a1="..."
    type=CWD       ... cwd="..."
    type=PATH      ... name="..."  (appears twice: binary + ld-linux)
    type=PROCTITLE ... proctitle="..." or proctitle=<hex>

Record order: audit.log = SYSCALL first. ausearch reverses. Parser is
order-independent — searches by type= prefix.

parent_exe: auditd gives ppid only. Resolution via pid->exe cache is the
daemon's responsibility. _assemble() always returns parent_exe="" — the daemon
injects the resolved value via dataclasses.replace() after assembly.

Buffer flush: _tail() runs as a background asyncio Task feeding a Queue.
_run() reads from the Queue with a timeout. On timeout, the buffer is flushed.
This avoids the asyncio.wait_for() + async-generator cancellation bug where
cancelling __anext__() corrupts the generator and causes immediate StopAsyncIteration.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator
from pathlib import Path

from ..events import ExecEvent
from .base import EventSource

log = logging.getLogger("habitd.source.logparse")

_SENTINEL = object()  # signals _tail Task completion to _run

# audit(epoch.ms:serial) — the event group key
_AUDIT_ID = re.compile(r"audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\)")
# Generic key=value / key="value" extractor
_KV = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


class LogParseSource(EventSource):
    def __init__(self, config) -> None:
        super().__init__(config)
        self._tail_task: asyncio.Task | None = None

    def events(self) -> AsyncIterator[ExecEvent]:
        return self._run()

    async def aclose(self) -> None:
        if self._tail_task is not None:
            self._tail_task.cancel()
            try:
                await self._tail_task
            except (asyncio.CancelledError, Exception):
                pass

    async def _run(self) -> AsyncIterator[ExecEvent]:
        path = Path(self.config.get("source_logparse.audit_log_path"))
        audit_key = self.config.get("daemon.audit_key", "habitd_exec")
        flush_timeout = float(self.config.get("source_logparse.flush_timeout", 30.0))

        queue: asyncio.Queue = asyncio.Queue(maxsize=4096)

        # Run _tail as a background task feeding the queue.
        # This avoids the asyncio.wait_for + async-generator cancellation bug.
        self._tail_task = asyncio.create_task(self._feed(path, queue))

        records: list[str] = []
        current_id: str | None = None

        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=flush_timeout)
            except asyncio.TimeoutError:
                # No new line for flush_timeout seconds — flush buffered records.
                if records:
                    ev = self._assemble(records, audit_key)
                    records = []
                    current_id = None
                    if ev is not None:
                        yield ev
                continue

            if item is _SENTINEL:
                # _tail Task finished (e.g. rotation loop exited unexpectedly).
                if records:
                    ev = self._assemble(records, audit_key)
                    if ev is not None:
                        yield ev
                break

            line: str = item
            m = _AUDIT_ID.search(line)
            if not m:
                continue
            ev_id = m.group("serial")

            # New event id => flush the previous group first.
            if current_id is not None and ev_id != current_id:
                ev = self._assemble(records, audit_key)
                records = []
                if ev is not None:
                    yield ev
            current_id = ev_id
            records.append(line)

    async def _feed(self, path: Path, queue: asyncio.Queue) -> None:
        """Background task: put lines from _tail into the queue.

        Logs a warning when the queue is filling up (consumer-side backpressure),
        because at maxsize put() will block and event ingestion stalls.
        """
        warned_full = False
        try:
            async for line in self._tail(path):
                qsize = queue.qsize()
                # Warn once when we cross 75% capacity; reset when we drain below 50%.
                if qsize > queue.maxsize * 0.75 and not warned_full:
                    log.warning(
                        "event queue %d%% full (%d/%d) — consumer is falling behind, "
                        "events may stall or be dropped",
                        int(qsize / queue.maxsize * 100), qsize, queue.maxsize,
                    )
                    warned_full = True
                elif qsize < queue.maxsize * 0.5 and warned_full:
                    log.info("event queue drained below 50%% — backpressure resolved")
                    warned_full = False
                await queue.put(line)
        finally:
            await queue.put(_SENTINEL)

    async def _tail(self, path: Path) -> AsyncIterator[str]:
        """Follow a file like `tail -f`, surviving log rotation indefinitely.

        First open: seek to EOF (we only want new events, not the backlog).
        Rotation-reopen: seek to beginning (events written to the new file
        before we open it must not be missed).
        """
        seek_to_end = True  # only on first open

        while True:
            while not path.exists():
                log.warning("audit log %s not present; waiting", path)
                await asyncio.sleep(2)

            inode = path.stat().st_ino
            log.info("opening audit log %s (inode=%d seek_to_end=%s)",
                     path, inode, seek_to_end)

            with path.open("r", errors="replace") as fh:
                if seek_to_end:
                    fh.seek(0, 2)
                seek_to_end = False

                while True:
                    line = fh.readline()
                    if line:
                        yield line.rstrip("\n")
                        continue

                    await asyncio.sleep(0.2)

                    try:
                        new_inode = path.stat().st_ino
                    except FileNotFoundError:
                        log.warning("audit log %s disappeared; waiting for new file", path)
                        break

                    if new_inode != inode:
                        while True:
                            line = fh.readline()
                            if not line:
                                break
                            yield line.rstrip("\n")
                        log.info(
                            "audit log rotated (old inode=%d new inode=%d); reopening",
                            inode, new_inode,
                        )
                        break

    def _assemble(self, records: list[str], audit_key: str) -> ExecEvent | None:
        """Build an ExecEvent from a group of records sharing one audit id."""
        syscall = next((r for r in records if "type=SYSCALL" in r), None)
        if syscall is None:
            return None

        if audit_key:
            if f'key="{audit_key}"' not in syscall and f"key={audit_key}" not in syscall:
                return None

        fields = {k: (q or u) for k, q, u in _KV.findall(syscall)}

        cwd = ""
        cwd_rec = next((r for r in records if "type=CWD" in r), None)
        if cwd_rec:
            cwd_fields = {k: (q or u) for k, q, u in _KV.findall(cwd_rec)}
            cwd = cwd_fields.get("cwd", "")

        try:
            id_m = _AUDIT_ID.search(syscall)
            ts = float(id_m.group("epoch")) if id_m else 0.0
            return ExecEvent(
                timestamp=ts,
                pid=int(fields.get("pid", -1)),
                ppid=int(fields.get("ppid", -1)),
                uid=int(fields.get("uid", -1)),
                exe=fields.get("exe", ""),
                comm=fields.get("comm", ""),
                parent_exe="",
                parent_comm="",
                cwd=cwd,
                args=(),
                audit_id=id_m.group(0) if id_m else "",
            )
        except (ValueError, KeyError) as exc:
            log.debug("could not assemble event: %s", exc)
            return None
