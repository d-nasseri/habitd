"""habitd daemon — the wiring.

Pipeline per event:

    source ──► ExecEvent (parent_exe="" from source)
                  │
                  ▼
            read /proc/<pid>/stat for current start_time (TOCTOU-checked)
                  │
                  ▼
            ProcessCache lookup (ppid => parent_exe)
                  │
                  ▼
            in-place execve detection (same descriptor, different exe)
                  │
                  ▼
            cache updated (pid => exe + start_time)
                  │
                  ▼
            Layer 1 static check ──┐
                  │                │ merge
            Layer 2 baseline check ┘
                  │
            anomalous? ──no──► record into baseline, done
                  │ yes
                  ▼
            persist alert in DB (with siem_emitted=0)
                  │
                  ▼
            emit Wazuh JSON + ntfy push (async, fire-and-forget)
                  │
                  ▼
            mark alert siem_emitted=1

ProcessCache identity:
  Each PID's entry stores (exe, start_time_jiffies). PID recycling shows up as
  start_time mismatch → silent cache update. In-place execve shows up as same
  start_time but new exe → suspicious. Process age (now - start_time) provides
  a second signal even when the cache has no prior entry.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Optional

from .alert import AlertEngine
from .config import Config
from .db import Store
from .detection import (
    check_baseline,
    check_static,
    inplace_execve_verdict,
    known_malicious_verdict,
    parent_unresolved_verdict,
)
from .events import ExecEvent
from .sources import get_source
from .utils import path as _path

log = logging.getLogger("habitd")

MAX_CACHE_SIZE = 8192          # generous, prevents LRU eviction of long-lived daemons
HZ = os.sysconf("SC_CLK_TCK")  # clock ticks per second (kernel jiffies, usually 100)

# Process age above which an execve is treated as in-place by definition.
# Most normal execves happen within a fraction of a second of process creation
# (fork → execve). A process older than this performing an execve is
# anomalous unless explicitly whitelisted.
IN_PLACE_AGE_THRESHOLD_SEC = 60.0

# Tolerance for TOCTOU detection: how much later /proc start_time may be
# vs auditd event timestamp before we mark the /proc data as stale.
TOCTOU_TOLERANCE_SEC = 2.0


# --- /proc helpers ------------------------------------------------------- #

def _get_boot_time() -> float:
    """Unix epoch of system boot (constant for the daemon's life)."""
    try:
        with open("/proc/stat", "r") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except OSError as exc:
        log.warning("could not read /proc/stat: %s", exc)
    return 0.0


def _read_proc_start_time(pid: int) -> Optional[int]:
    """Read field 22 (start_time, in jiffies since boot) from /proc/<pid>/stat.

    The comm field (#2) is in parentheses and can contain ANY character
    including ')' and spaces — a process can call prctl(PR_SET_NAME, "evil ) (")
    to weaponize naive parsers. We use rfind(')') to anchor on the LAST
    closing paren, which is the only safe approach.

    Returns None if the process doesn't exist, we can't read it, or the
    format is unexpectedly malformed.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read().decode("utf-8", errors="replace")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    except OSError:
        return None
    rparen = data.rfind(")")
    if rparen == -1:
        return None
    # After the closing paren there's " STATE PPID PGRP ... STARTTIME ..."
    # STARTTIME is field 22 overall, so field index 19 (0-based) after comm.
    tail_fields = data[rparen + 1:].split()
    if len(tail_fields) < 20:
        return None
    try:
        return int(tail_fields[19])
    except (ValueError, IndexError):
        return None


# --- ProcessCache -------------------------------------------------------- #

@dataclass(slots=True)
class CachedProcess:
    exe: str
    start_time_jiffies: int  # constant per process descriptor


class ProcessCache:
    """Bounded pid -> (exe, start_time) cache with LRU eviction.

    Process identity is (pid, start_time_jiffies). Recycled PIDs have a
    different start_time, so we can distinguish recycling from in-place
    image replacement.

    /proc is the source of truth — this cache exists as an optimization for
    parent resolution (ppid → exe) and to provide a prior data point for
    detection. Detection-critical comparisons re-read /proc at event time.
    """

    def __init__(self, maxsize: int = MAX_CACHE_SIZE) -> None:
        self._data: OrderedDict[int, CachedProcess] = OrderedDict()
        self._maxsize = maxsize
        self._boot_time = _get_boot_time()

    @property
    def boot_time(self) -> float:
        return self._boot_time

    def get_exe(self, pid: int) -> str:
        """Return cached exe for PID, or '' if unknown. LRU-touches."""
        entry = self._data.get(pid)
        if entry is None:
            return ""
        self._data.move_to_end(pid)
        return entry.exe

    def get(self, pid: int) -> Optional[CachedProcess]:
        """Return full cached entry, or None. LRU-touches."""
        entry = self._data.get(pid)
        if entry is None:
            return None
        self._data.move_to_end(pid)
        return entry

    def set(self, pid: int, exe: str, start_time_jiffies: int) -> None:
        if pid in self._data:
            self._data.move_to_end(pid)
        self._data[pid] = CachedProcess(exe=exe, start_time_jiffies=start_time_jiffies)
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    def start_time_to_unix(self, start_jiffies: int) -> float:
        """Convert /proc jiffies-since-boot to unix epoch seconds."""
        return self._boot_time + (start_jiffies / HZ)

    def start_time_to_age_sec(self, start_jiffies: int) -> float:
        """Seconds since the process started (now - start_time)."""
        return time.time() - self.start_time_to_unix(start_jiffies)

    def seed_from_proc(self) -> int:
        """Walk /proc at startup to populate (pid, exe, start_time)."""
        count = 0
        try:
            entries = list(os.scandir("/proc"))
        except OSError as exc:
            log.warning("could not scan /proc: %s", exc)
            return 0
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                exe = os.readlink(f"/proc/{entry.name}/exe")
            except OSError:
                continue
            start = _read_proc_start_time(int(entry.name))
            if start is None:
                continue
            self.set(int(entry.name), exe, start)
            count += 1
        return count


# --- Backward-compatibility shim ---------------------------------------- #
# Old PidCache name kept so external CLI code (and tests) referencing the
# legacy class still work. New code should use ProcessCache directly.

class PidCache(ProcessCache):
    """Deprecated: use ProcessCache. Kept for backward compatibility."""

    def get(self, pid: int) -> str:  # type: ignore[override]
        # Old API returned str ("" if absent). Keep that contract.
        return self.get_exe(pid)

    def set(self, pid: int, exe: str, start_time_jiffies: int | None = None) -> None:  # type: ignore[override]
        # Old API took only (pid, exe). For shim callers, look up start_time now.
        if start_time_jiffies is None:
            start_time_jiffies = _read_proc_start_time(pid) or 0
        super().set(pid, exe, start_time_jiffies)


# --- Daemon -------------------------------------------------------------- #

class Daemon:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.store = Store(config.get("storage.db_path"))
        self.alerts = AlertEngine(
            json_log_path=config.get("alerting.json_log"),
            syslog=config.get("alerting.syslog", False),
            ntfy_url=config.get("alerting.ntfy_url", None),
            ntfy_topic=config.get("alerting.ntfy_topic", None),
            ntfy_token=config.get("alerting.ntfy_token", None),
        )
        self.source = get_source(config)
        self.process_cache = ProcessCache()
        self._task: asyncio.Task | None = None
        self._initial_phase_seconds = (
            float(config.get("learning.initial_phase_hours", 168)) * 3600
        )
        # Whitelist of exe paths legitimately performing in-place execve
        # (service managers re-execing themselves on upgrade, etc.).
        wl = config.get("detection.inplace_execve_whitelist", []) or []
        self._inplace_whitelist = set(wl)

    # Provide the legacy attribute name for tests / external code
    # that referenced self.pid_cache.
    @property
    def pid_cache(self) -> ProcessCache:
        return self.process_cache

    async def run(self) -> None:
        self.store.connect()
        self._task = asyncio.current_task()
        self._install_signal_handlers()

        # Replay any DB-persisted alerts that didn't make it to SIEM (crash recovery).
        replayed = self._replay_unemitted_alerts()
        if replayed:
            log.info("replayed %d alert(s) not emitted before last shutdown", replayed)

        seeded = self.process_cache.seed_from_proc()
        log.info(
            "habitd started — source=%s db=%s cache_seeded=%d boot_time=%.0f hz=%d",
            self.config.get("daemon.source"),
            self.config.get("storage.db_path"),
            seeded,
            self.process_cache.boot_time,
            HZ,
        )
        try:
            await self._consume()
        except asyncio.CancelledError:
            log.info("shutdown signal received")
        finally:
            self.alerts.close()
            await self.source.aclose()
            self.store.close()
            log.info("habitd stopped")

    async def _consume(self) -> None:
        async for ev in self.source.events():
            try:
                self._handle(ev)
            except Exception:
                log.exception("error handling event %s", ev.audit_id)

    def _replay_unemitted_alerts(self) -> int:
        """Send any DB-persisted alerts where siem_emitted=0 (crash recovery)."""
        rows = self.store.fetch_unemitted_alerts()
        count = 0
        for row in rows:
            try:
                record = json.loads(row["raw_event"])
                self.alerts.emit(record)
                self.store.mark_alert_emitted(row["id"])
                count += 1
            except Exception:
                log.exception("failed to replay alert id=%s", row["id"])
        return count

    def _handle(self, ev: ExecEvent) -> None:
        # --- Read current start_time from /proc (source of truth) -----------
        current_start = _read_proc_start_time(ev.pid)

        # TOCTOU check: if /proc shows a start_time AFTER our event timestamp,
        # the PID was recycled between event capture and our read. The /proc
        # data describes a DIFFERENT process now occupying this PID.
        stat_is_stale = False
        if current_start is not None and ev.timestamp > 0:
            proc_start_unix = self.process_cache.start_time_to_unix(current_start)
            if proc_start_unix > ev.timestamp + TOCTOU_TOLERANCE_SEC:
                stat_is_stale = True
                current_start = None  # don't trust it for detection

        # --- Parent resolution (uses cache, not /proc) ----------------------
        parent_exe = self.process_cache.get_exe(ev.ppid)
        parent_comm = os.path.basename(parent_exe) if parent_exe else ""
        parent_resolved = bool(parent_exe)

        # --- In-place execve detection -------------------------------------
        inplace_detected = False
        inplace_detail = ""

        if current_start is not None and ev.exe not in self._inplace_whitelist:
            prior = self.process_cache.get(ev.pid)

            if prior is not None and prior.start_time_jiffies == current_start \
                    and prior.exe and prior.exe != ev.exe:
                # Same descriptor (same start_time), exe path changed.
                inplace_detected = True
                inplace_detail = f"prior_exe={prior.exe}"
            else:
                # No prior cache entry — fall back to process-age heuristic.
                # A process older than the threshold doing an execve is
                # in-place by definition (it pre-existed the execve event).
                age = self.process_cache.start_time_to_age_sec(current_start)
                if age > IN_PLACE_AGE_THRESHOLD_SEC:
                    inplace_detected = True
                    inplace_detail = f"process_age={age:.0f}s"

        # --- Cache update ---------------------------------------------------
        if ev.exe and current_start is not None and not stat_is_stale:
            self.process_cache.set(ev.pid, ev.exe, current_start)

        # --- Event enrichment ----------------------------------------------
        ev = replace(ev, parent_exe=parent_exe, parent_comm=parent_comm)

        # --- Baseline lookup -----------------------------------------------
        existing = self.store.lookup(ev) if parent_resolved else None
        seen = existing is not None and existing["status"] in ("confirmed", "pending")
        known_malicious = existing is not None and existing["status"] == "malicious"

        # --- Layer 1 -------------------------------------------------------
        verdict = check_static(ev)

        if inplace_detected:
            verdict = verdict.merge(inplace_execve_verdict(inplace_detail))

        # --- Layer 2 -------------------------------------------------------
        if parent_resolved:
            verdict = verdict.merge(check_baseline(ev, seen=seen))
        else:
            verdict = verdict.merge(parent_unresolved_verdict())

        if known_malicious:
            verdict = verdict.merge(known_malicious_verdict())

        # Benign event AND parent was resolved → update baseline, done.
        if not verdict.anomalous:
            if parent_resolved:
                self.store.record(ev, status="confirmed" if seen else "pending")
            return

        in_learning = self._in_learning_phase()
        level = self.alerts.severity(verdict, in_learning_phase=in_learning)
        record = self.alerts.build(ev, verdict, level)

        # --- Atomic write order: DB FIRST, SIEM second (#7) ----------------
        # On crash between these, the DB has the alert with siem_emitted=0
        # and we replay on next startup. If we did it the other way around,
        # Wazuh could have an alert we don't, and we'd never reconcile.
        alert_id = self.store.save_alert(
            timestamp=ev.timestamp or time.time(),
            level=level,
            detection_layer=verdict.layer,
            ev=ev,
            reasons_json=json.dumps([str(r) for r in verdict.reasons]),
            raw_json=json.dumps(record),
        )

        # Emit to SIEM only if alert output is enabled (runtime-toggleable
        # via `habitd alerts on/off`).
        if self._alerts_enabled():
            self.alerts.emit(record, want_ntfy=self._ntfy_enabled())
            if alert_id is not None:
                self.store.mark_alert_emitted(alert_id)

        if parent_resolved and not known_malicious:
            self.store.record(ev, status="pending")

        log.info(
            "alert level=%s layer=%s exe=%s parent=%s reasons=%s",
            level, verdict.layer, _path(ev.exe), _path(ev.parent_exe),
            [str(r) for r in verdict.reasons],
        )

    # --- Runtime toggle queries -------------------------------------------- #

    def _in_learning_phase(self) -> bool:
        override = self.store.get_meta("learning_enabled", "")
        if override == "1":
            return True
        if override == "0":
            return False
        if self.config.get("learning.mode") == "frozen":
            return False
        return (time.time() - self.store.installed_at()) < self._initial_phase_seconds

    def _alerts_enabled(self) -> bool:
        return self.store.get_meta("alerts_enabled", "1") == "1"

    def _ntfy_enabled(self) -> bool:
        return self.store.get_meta("ntfy_enabled", "1") == "1"

    # --- Signals ---------------------------------------------------------- #

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._request_stop)

    def _request_stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
