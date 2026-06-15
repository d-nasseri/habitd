"""Alert engine.

Responsibilities:
  - severity assignment from reason codes (not text)
  - JSON record construction with Wazuh-safe field names
  - emit to local JSON log (synchronous, cheap)
  - emit to ntfy push (async via thread pool, deduplicated)

Why a thread pool for ntfy?
  The daemon runs an asyncio event loop. Calling urllib.request.urlopen()
  synchronously inside that loop blocks the loop for up to the request
  timeout (5s). During that window no new events can be consumed, which
  means a slow ntfy server can stall detection. Submitting the push to a
  worker thread keeps the event loop free.

Why dedup?
  A Layer 1 hit in a tight loop (compromised service in `while true; do
  bash; done`) generates hundreds of identical alerts per second. Pushing
  every single one to ntfy floods the device and exceeds ntfy.sh rate
  limits. Dedup suppresses identical alerts within a 60s window and
  attaches a (+N suppressed) hint to the next push.

Dedup applies ONLY to ntfy. The JSON log and DB record every alert
unconditionally — SIEM and forensics need completeness.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import time
import urllib.error
import urllib.request
from typing import Optional

from .detection import (
    R_INPLACE_EXECVE,
    R_KNOWN_MALICIOUS,
    R_PARENT_UNRESOLVED,
    R_SUSPICIOUS_PATH,
    Verdict,
)
from .events import ExecEvent

log = logging.getLogger("habitd.alert")

LEVELS = ("informational", "low", "medium", "high", "critical")
NTFY_PUSH_LEVELS = {"medium", "high", "critical"}

DEDUP_WINDOW_SEC = 60.0
DEDUP_TRIM_AT_SIZE = 4096  # trim expired entries when dict grows past this


class AlertEngine:
    def __init__(
        self,
        json_log_path: str,
        syslog: bool = False,
        ntfy_url: Optional[str] = None,
        ntfy_topic: Optional[str] = None,
        ntfy_token: Optional[str] = None,
    ) -> None:
        self.json_log_path = json_log_path
        self.syslog = syslog
        self.ntfy_url = ntfy_url.rstrip("/") if ntfy_url else None
        self.ntfy_topic = ntfy_topic
        self.ntfy_token = ntfy_token

        # Worker pool for non-blocking ntfy pushes. Unbounded internal queue;
        # if ntfy is unreachable, futures pile up in memory (acceptable —
        # ntfy push isn't critical and we don't want to lose events).
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="habitd-ntfy",
        )

        # Dedup state: key -> (last_push_unix, suppressed_count_since)
        self._dedup: dict[tuple, tuple[float, int]] = {}

    # --- severity ---------------------------------------------------------- #

    def severity(self, verdict: Verdict, *, in_learning_phase: bool) -> str:
        """Severity from reason codes, not substring matches.

        Decoupled from reason text so renaming a message can never silently
        flip a severity classification.
        """
        codes = {r.code for r in verdict.reasons}

        if R_KNOWN_MALICIOUS in codes:
            return "critical"
        if R_INPLACE_EXECVE in codes:
            return "high"
        if R_SUSPICIOUS_PATH in codes:
            return "high"
        if verdict.layer == "layer1_static":
            return "high"

        # Parent-unresolved is data-quality, not a real anomaly. Downgrade
        # so warmup noise doesn't drown real signals.
        if R_PARENT_UNRESOLVED in codes:
            return "low"

        if verdict.layer == "layer2_baseline":
            return "informational" if in_learning_phase else "medium"
        return "low"

    # --- record building --------------------------------------------------- #

    def build(self, ev: ExecEvent, verdict: Verdict, level: str) -> dict:
        record = {
            "timestamp": _iso(ev.timestamp or time.time()),
            "habitd_level": level,
            "process_name": ev.comm,
            "pid": ev.pid,
            "parent_name": ev.parent_comm,
            "parent_pid": ev.ppid,
            "uid": ev.uid,
            "executable_path": ev.exe,
            "parent_executable_path": ev.parent_exe,
            "detection_layer": verdict.layer,
            "secondary_detection_layer": verdict.secondary_layer,
            "reasons": [str(r) for r in verdict.reasons],
            "reason_codes": [r.code for r in verdict.reasons],
            "audit_id": ev.audit_id,
            "tool": "habitd",
        }
        if ev.args:
            record["args"] = list(ev.args)
        return record

    # --- emit -------------------------------------------------------------- #

    def emit(self, record: dict, *, want_ntfy: bool = True) -> None:
        """Write to JSON log (sync) and optionally trigger ntfy push (async).

        `want_ntfy=False` lets the daemon skip pushes per runtime toggle
        (`habitd ntfy off`) without affecting SIEM output.
        """
        line = json.dumps(record, separators=(",", ":"))
        try:
            with open(self.json_log_path, "a") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            log.error("failed to write alert: %s", exc)

        if self.syslog:
            log.warning("ALERT %s", line)

        if want_ntfy and record.get("habitd_level") in NTFY_PUSH_LEVELS:
            self._maybe_push_ntfy(record)

    def close(self) -> None:
        """Shut down the worker pool. Called by daemon on stop."""
        self._executor.shutdown(wait=True, cancel_futures=False)

    # --- ntfy dedup + dispatch -------------------------------------------- #

    def _maybe_push_ntfy(self, record: dict) -> None:
        """Apply 60s dedup window per (level, exe, parent_exe, uid) key.

        On suppress: increment counter, do nothing else.
        On allow: include (+N suppressed) hint in next push, reset counter.
        """
        key = (
            record.get("habitd_level"),
            record.get("executable_path"),
            record.get("parent_executable_path"),
            record.get("uid"),
        )
        now = time.time()
        last_push, suppressed = self._dedup.get(key, (0.0, 0))

        if now - last_push < DEDUP_WINDOW_SEC:
            self._dedup[key] = (last_push, suppressed + 1)
            return

        # Outside window — push, optionally with suppressed-count hint.
        suppressed_hint = ""
        if suppressed > 0:
            suppressed_hint = (
                f"  (+{suppressed} identical alert(s) suppressed in the last "
                f"{int(DEDUP_WINDOW_SEC)}s)"
            )

        self._dedup[key] = (now, 0)
        self._maybe_trim_dedup(now)

        # Fire-and-forget; executor.submit never blocks.
        self._executor.submit(self._push_ntfy_sync, record, suppressed_hint)

    def _maybe_trim_dedup(self, now: float) -> None:
        """Drop dedup entries older than 2× the window to bound memory."""
        if len(self._dedup) < DEDUP_TRIM_AT_SIZE:
            return
        threshold = now - (DEDUP_WINDOW_SEC * 2)
        expired = [k for k, (t, _) in self._dedup.items() if t < threshold]
        for k in expired:
            del self._dedup[k]

    def _push_ntfy_sync(self, record: dict, suppressed_hint: str = "") -> None:
        """Blocking HTTP POST to ntfy. Runs in worker thread, never on the loop."""
        if not self.ntfy_url or not self.ntfy_topic:
            log.debug("ntfy not configured, skipping push")
            return

        level = record.get("habitd_level", "?")
        proc = record.get("process_name", "?")
        parent = record.get("parent_name", "?")
        reasons = "; ".join(record.get("reasons", []))

        title = f"habitd [{level.upper()}] {proc}"
        body = f"Parent: {parent}\n{reasons}{suppressed_hint}"
        priority_map = {"critical": "urgent", "high": "high", "medium": "default"}
        priority = priority_map.get(level, "default")
        url = f"{self.ntfy_url}/{self.ntfy_topic}"
        headers = {
            "Title": title,
            "Priority": priority,
            "Tags": f"warning,{level}",
            "Content-Type": "text/plain",
        }
        if self.ntfy_token:
            headers["Authorization"] = f"Bearer {self.ntfy_token}"

        log.debug("ntfy push → %s", url)
        try:
            req = urllib.request.Request(
                url, data=body.encode(),
                headers=headers, method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                log.debug("ntfy response: %d", resp.status)
        except urllib.error.URLError as exc:
            log.warning("ntfy push failed: %s", exc)
        except Exception as exc:
            log.warning("ntfy push unexpected error: %s", exc)


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch))
