"""SQLite baseline + alert store.

Schema:
  - baseline : one row per (parent_exe, exe, uid) tuple ever confirmed/seen
  - alerts   : append-only log of every alert raised
                  + siem_emitted flag for crash-recovery replay
  - meta     : runtime toggles + installed_at fallback

Review workflow (Continuous Learning) is modeled by baseline.status:
  pending  -> seen, awaiting admin decision
  confirmed-> admin marked legitimate; never alerts again
  malicious-> admin marked bad; retained as IOC

Concurrency: single-writer daemon, default isolation. WAL mode so read-only
CLI / GUI can query without blocking.

installed_at semantics:
  Sourced from a sentinel file under /var/lib/habitd/ (or /etc/habitd/),
  NOT from the DB itself — deleting the DB to reset the learning window no
  longer works without also removing the marker file. Recommended hardening:
  `chattr +i /var/lib/habitd/.install_marker` once after first start.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Optional

from .events import ExecEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    id           INTEGER PRIMARY KEY,
    parent_exe   TEXT    NOT NULL,
    exe          TEXT    NOT NULL,
    uid          INTEGER NOT NULL,
    first_seen   REAL    NOT NULL,
    last_seen    REAL    NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1,
    status       TEXT    NOT NULL DEFAULT 'pending',
    UNIQUE(parent_exe, exe, uid)
);

CREATE INDEX IF NOT EXISTS idx_baseline_status ON baseline(status);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY,
    timestamp       REAL    NOT NULL,
    level           TEXT    NOT NULL,
    detection_layer TEXT    NOT NULL,
    pid             INTEGER,
    ppid            INTEGER,
    uid             INTEGER,
    exe             TEXT,
    parent_exe      TEXT,
    reasons         TEXT,
    raw_event       TEXT,
    siem_emitted    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_unemitted
    ON alerts(siem_emitted) WHERE siem_emitted = 0;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Marker files used to derive installed_at outside the DB. First existing
# path wins. The /etc location is preferred (independent of state dir, harder
# to wipe in a single rm -rf).
INSTALL_MARKER_PATHS = (
    Path("/etc/habitd/.install_timestamp"),
    Path("/var/lib/habitd/.install_marker"),
)


class Store:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._ensure_install_marker()
        # Fallback: also keep DB-stored installed_at for systems where /etc
        # and /var/lib markers can't be created (e.g. tests on tmpfs).
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('installed_at', ?)",
            (str(time.time()),),
        )

    def _migrate(self) -> None:
        """Schema migration for upgrades from V0.1 / V0.2 baselines.

        Idempotent — runs on every connect, no-ops if columns already exist.
        """
        existing_cols = {
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(alerts)").fetchall()
        }
        if "siem_emitted" not in existing_cols:
            self.conn.execute(
                "ALTER TABLE alerts ADD COLUMN siem_emitted INTEGER NOT NULL DEFAULT 0"
            )

    def _ensure_install_marker(self) -> None:
        """Create the install-timestamp marker file if no marker exists.

        Best-effort: if neither path is writable (e.g. running unprivileged
        in tests), fall through and let installed_at() use the DB value.
        """
        for path in INSTALL_MARKER_PATHS:
            if path.exists():
                return
        # No marker yet — try to create one.
        for path in INSTALL_MARKER_PATHS:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
                return
            except OSError:
                continue

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Store.connect() not called")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # --- baseline ------------------------------------------------------------

    def lookup(self, ev: ExecEvent) -> sqlite3.Row | None:
        parent_exe, exe, uid = ev.baseline_key()
        cur = self.conn.execute(
            "SELECT * FROM baseline WHERE parent_exe=? AND exe=? AND uid=?",
            (parent_exe, exe, uid),
        )
        return cur.fetchone()

    def record(self, ev: ExecEvent, status: str = "pending") -> bool:
        parent_exe, exe, uid = ev.baseline_key()
        cur = self.conn.execute(
            """
            INSERT INTO baseline (parent_exe, exe, uid, first_seen, last_seen, count, status)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(parent_exe, exe, uid) DO UPDATE SET
                last_seen = excluded.last_seen,
                count     = count + 1
            """,
            (parent_exe, exe, uid, ev.timestamp, ev.timestamp, status),
        )
        return self.conn.total_changes > 0 and cur.lastrowid is not None

    def installed_at(self) -> float:
        """Return the install epoch from the most tamper-resistant source."""
        for path in INSTALL_MARKER_PATHS:
            try:
                return path.stat().st_mtime
            except OSError:
                continue
        # Fallback to DB-stored value
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='installed_at'"
        ).fetchone()
        return float(row["value"]) if row else time.time()

    # --- meta (runtime state) ------------------------------------------------

    def get_meta(self, key: str, default: str = "") -> str:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # --- alerts --------------------------------------------------------------

    def save_alert(
        self,
        *,
        timestamp: float,
        level: str,
        detection_layer: str,
        ev: ExecEvent,
        reasons_json: str,
        raw_json: str,
    ) -> Optional[int]:
        """Persist alert with siem_emitted=0. Returns the new row's id."""
        cur = self.conn.execute(
            """
            INSERT INTO alerts
              (timestamp, level, detection_layer, pid, ppid, uid, exe, parent_exe,
               reasons, raw_event, siem_emitted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                timestamp, level, detection_layer,
                ev.pid, ev.ppid, ev.uid, ev.exe, ev.parent_exe,
                reasons_json, raw_json,
            ),
        )
        return cur.lastrowid

    def fetch_unemitted_alerts(self) -> list[sqlite3.Row]:
        """Return alerts that were persisted but never made it to SIEM.

        Called on daemon startup for crash-recovery replay (#7).
        """
        cur = self.conn.execute(
            "SELECT id, raw_event FROM alerts WHERE siem_emitted = 0 ORDER BY id"
        )
        return cur.fetchall()

    def mark_alert_emitted(self, alert_id: int) -> None:
        self.conn.execute(
            "UPDATE alerts SET siem_emitted = 1 WHERE id = ?",
            (alert_id,),
        )
