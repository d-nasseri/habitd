"""habitd CLI entry point.

  habitd run                                     # run the daemon
  habitd status                                  # daemon/db summary + toggle state
  habitd baseline                                # dump baseline contents
  habitd review                                  # interactive review of pending tuples
  habitd whitelist <parent_exe> <exe> <uid|user> # mark tuple as confirmed-legitimate
  habitd mark-malicious <parent_exe> <exe> <uid|user>  # mark tuple as known IOC
  habitd uid <username>                          # resolve a username to its UID
  habitd log [-n N]                              # tail alert log, pretty-printed
  habitd flush                                   # flush pending DB writes to disk
  habitd learning on|off                         # toggle learning phase
  habitd alerts on|off                           # toggle SIEM output
  habitd ntfy on|off                             # toggle push notifications

CLI baseline-management commands share the same Store so they work against a
running daemon (WAL mode permits concurrent reads). UID arguments accept
either a numeric UID or a username resolvable via getpwnam().
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time

from .config import Config
from .daemon import Daemon
from .db import Store
from .utils import path as _path


# ── ANSI colours ──────────────────────────────────────────────────────────────
_C_RESET   = "\033[0m"
_C_GREEN   = "\033[0;32m"
_C_RED     = "\033[0;31m"
_C_YELLOW  = "\033[0;33m"
_C_DIM     = "\033[2m"
_C_BOLD    = "\033[1m"
_C_PATH    = "\033[38;5;110m"   # blue-grey — same as daemon

_LEVEL_COLOR = {
    "high":          "\033[0;31m",   # red
    "medium":        "\033[0;33m",   # yellow
    "low":           "\033[0;33m",   # yellow
    "informational": "\033[0;32m",   # green
}


def _setup_logging(cfg: Config) -> None:
    level = getattr(logging, str(cfg.get("logging.level", "INFO")).upper(), logging.INFO)
    try:
        import colorlog
        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s%(reset)s %(name)s %(log_color)s%(levelname)s%(reset)s %(message)s",
            log_colors={
                "DEBUG":    "cyan",
                "INFO":     "green",
                "WARNING":  "yellow",
                "ERROR":    "red",
                "CRITICAL": "bold_red",
            },
        ))
        logging.root.setLevel(level)
        logging.root.addHandler(handler)
    except ImportError:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(name)s %(levelname)s %(message)s",
        )


# ── Learning / alerts state helpers ──────────────────────────────────────────

def _is_learning(store: Store, cfg: Config) -> bool:
    """Determine if the system is in learning phase.

    Priority: runtime override (habitd learning on/off) > config mode > timer.
    """
    override = store.get_meta("learning_enabled", "")
    if override == "1":
        return True
    if override == "0":
        return False
    # No runtime override — fall back to config + timer.
    if cfg.get("learning.mode") == "frozen":
        return False
    phase_seconds = float(cfg.get("learning.initial_phase_hours", 168)) * 3600
    return (time.time() - store.installed_at()) < phase_seconds


def _are_alerts_enabled(store: Store) -> bool:
    """Check if alert output to SIEM is enabled (default: yes)."""
    return store.get_meta("alerts_enabled", "1") == "1"


def _print_learning_hint(store: Store, cfg: Config) -> None:
    """Print a one-line learning/alerts status hint when noteworthy."""
    learning = _is_learning(store, cfg)
    alerts = _are_alerts_enabled(store)

    parts = []
    if learning:
        parts.append(f"  {_C_GREEN}⚠ Learning phase ACTIVE{_C_RESET}"
                     f" — new behavior is informational only")
    if not alerts:
        parts.append(f"  {_C_RED}✗ Alert output DISABLED{_C_RESET}"
                     f" — SIEM is not receiving events")
    for p in parts:
        print(p)
    if parts:
        print()


# ── CLI entry point ──────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="habitd",
        description="Behavioral Linux daemon — LotL detection via auditd baseline learning.",
    )
    parser.add_argument("--config", default="/etc/habitd/config.yaml")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # run
    sub.add_parser("run", help="start the daemon")

    # status
    sub.add_parser("status", help="daemon/db summary + learning/alerts state")

    # baseline
    sub.add_parser("baseline", help="dump baseline contents")

    # review
    sub.add_parser("review", help="interactive review of pending baseline tuples")

    # whitelist
    p_wl = sub.add_parser("whitelist",
        help="confirm a tuple  (e.g. habitd whitelist /usr/bin/bash /usr/bin/curl 1000)")
    p_wl.add_argument("parent_exe", help="parent executable path")
    p_wl.add_argument("exe", help="child executable path")
    p_wl.add_argument("uid", help="numeric UID or username (e.g. 1000 or www-data)")

    # mark-malicious
    p_mal = sub.add_parser("mark-malicious",
        help="mark tuple as IOC  (e.g. habitd mark-malicious /usr/bin/bash /tmp/evil 1000)")
    p_mal.add_argument("parent_exe", help="parent executable path")
    p_mal.add_argument("exe", help="child executable path")
    p_mal.add_argument("uid", help="numeric UID or username (e.g. 1000 or www-data)")

    # uid
    p_uid = sub.add_parser("uid",
        help="resolve a username to its UID  (e.g. habitd uid www-data)")
    p_uid.add_argument("username", help="username to look up")

    # log
    p_log = sub.add_parser("log",
        help="tail alert log, pretty-printed  (e.g. habitd log -n 50)")
    p_log.add_argument("--lines", "-n", type=int, default=20,
                       help="initial lines to show (default: 20)")

    # flush
    sub.add_parser("flush", help="flush pending DB writes to disk (WAL checkpoint)")

    # learning
    p_learn = sub.add_parser("learning",
        help="toggle learning phase  (e.g. habitd learning off)")
    p_learn.add_argument("state", choices=["on", "off"],
                         help="'on' = force learning active, 'off' = production mode")

    # alerts
    p_alerts = sub.add_parser("alerts",
        help="toggle alert output to SIEM  (e.g. habitd alerts off)")
    p_alerts.add_argument("state", choices=["on", "off"],
                          help="'on' = emit to JSON log, 'off' = suppress SIEM output")

    # ntfy
    p_ntfy = sub.add_parser("ntfy",
        help="toggle push notifications  (e.g. habitd ntfy off)")
    p_ntfy.add_argument("state", choices=["on", "off"],
                        help="'on' = push to ntfy, 'off' = silence pushes (SIEM unaffected)")

    args = parser.parse_args(argv)

    # uid resolver doesn't need any config — handle it before Config.load()
    # so it works even on systems where /etc/habitd/config.yaml doesn't exist
    # yet (e.g. during first-time setup).
    if args.command == "uid":
        return _cmd_uid(args.username)

    cfg = Config.load(args.config)
    _setup_logging(cfg)

    match args.command:
        case "run" | None:
            try:
                asyncio.run(Daemon(cfg).run())
            except KeyboardInterrupt:
                pass
            return 0
        case "status":
            return _cmd_status(cfg)
        case "baseline":
            return _cmd_baseline_info(cfg)
        case "review":
            return _cmd_review_pending(cfg)
        case "whitelist":
            return _cmd_set_status(cfg, [args.parent_exe, args.exe, args.uid], "confirmed")
        case "mark-malicious":
            return _cmd_set_status(cfg, [args.parent_exe, args.exe, args.uid], "malicious")
        case "log":
            return _cmd_log(cfg, args.lines)
        case "flush":
            return _cmd_flush(cfg)
        case "learning":
            return _cmd_learning(cfg, args.state)
        case "alerts":
            return _cmd_alerts(cfg, args.state)
        case "ntfy":
            return _cmd_ntfy(cfg, args.state)
        case _:
            parser.print_help()
            return 1


# ── Subcommand implementations ───────────────────────────────────────────────

def _cmd_status(cfg: Config) -> int:
    store = Store(cfg.get("storage.db_path"))
    store.connect()
    c = store.conn
    total     = c.execute("SELECT COUNT(*) n FROM baseline").fetchone()["n"]
    pending   = c.execute("SELECT COUNT(*) n FROM baseline WHERE status='pending'").fetchone()["n"]
    confirmed = c.execute("SELECT COUNT(*) n FROM baseline WHERE status='confirmed'").fetchone()["n"]
    mal       = c.execute("SELECT COUNT(*) n FROM baseline WHERE status='malicious'").fetchone()["n"]
    alerts    = c.execute("SELECT COUNT(*) n FROM alerts").fetchone()["n"]

    learning = _is_learning(store, cfg)
    alerts_on = _are_alerts_enabled(store)
    installed = store.installed_at()
    installed_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(installed))

    # Learning: yellow = active (still calibrating), green = off (production).
    if learning:
        learn_str = f"{_C_GREEN}ON{_C_RESET}  {_C_DIM}(new behavior → informational){_C_RESET}"
    else:
        learn_str = f"{_C_RED}OFF{_C_RESET} {_C_DIM}(production mode){_C_RESET}"

    # Alerts: green = on, red = off (blind spot).
    if alerts_on:
        alert_str = f"{_C_GREEN}ON{_C_RESET}  {_C_DIM}(emitting to SIEM){_C_RESET}"
    else:
        alert_str = f"{_C_RED}OFF{_C_RESET} {_C_DIM}(SIEM not receiving events!){_C_RESET}"

    print(f"learning phase  : {learn_str}")
    print(f"alert output    : {alert_str}")
    print(f"baseline tuples : {total}")
    print(f"  pending       : {pending}")
    print(f"  confirmed     : {confirmed}")
    print(f"  malicious     : {mal}")
    print(f"alerts logged   : {alerts}")
    print(f"installed_at    : {installed_str}")
    store.close()
    return 0


def _cmd_baseline_info(cfg: Config) -> int:
    store = Store(cfg.get("storage.db_path"))
    store.connect()
    rows = store.conn.execute(
        "SELECT parent_exe, exe, uid, count, status FROM baseline ORDER BY count DESC"
    ).fetchall()
    for r in rows:
        print(f"[{r['status']:<9}] x{r['count']:<5} uid={r['uid']:<5} "
              f"{_path(r['parent_exe'])} -> {_path(r['exe'])}")
    store.close()
    return 0


def _resolve_uid(uid_or_user: str) -> int:
    """Accept either a numeric UID or a username, return integer UID.

    Raises ValueError with a clear message if neither parses.
    """
    if uid_or_user.isdigit():
        return int(uid_or_user)
    try:
        import pwd
        return pwd.getpwnam(uid_or_user).pw_uid
    except KeyError:
        raise ValueError(
            f"{uid_or_user!r} is neither a numeric UID nor a known username"
        ) from None


def _cmd_set_status(cfg: Config, triple: list[str], status: str) -> int:
    parent_exe, exe, uid_or_user = triple
    try:
        uid = _resolve_uid(uid_or_user)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    store = Store(cfg.get("storage.db_path"))
    store.connect()
    cur = store.conn.execute(
        "UPDATE baseline SET status=? WHERE parent_exe=? AND exe=? AND uid=?",
        (status, parent_exe, exe, uid),
    )
    if cur.rowcount == 0:
        store.conn.execute(
            "INSERT INTO baseline (parent_exe, exe, uid, first_seen, last_seen, count, status) "
            "VALUES (?, ?, ?, 0, 0, 0, ?)",
            (parent_exe, exe, uid, status),
        )
        print(f"inserted new tuple as {status} (uid={uid})")
    else:
        print(f"updated {cur.rowcount} tuple(s) to {status} (uid={uid})")
    store.close()
    return 0


def _cmd_uid(username: str) -> int:
    """Resolve a username to its UID for use in whitelist/mark-malicious commands."""
    try:
        uid = _resolve_uid(username)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"{username} → {uid}")
    return 0


def _cmd_learning(cfg: Config, state: str) -> int:
    """Toggle learning phase on or off (persisted in DB, picked up by running daemon)."""
    store = Store(cfg.get("storage.db_path"))
    store.connect()
    value = "1" if state == "on" else "0"
    store.set_meta("learning_enabled", value)
    if state == "on":
        print(f"{_C_GREEN}Learning phase ACTIVATED{_C_RESET}"
              f" — new behavior will be informational.")
    else:
        print(f"{_C_RED}Learning phase DEACTIVATED{_C_RESET}"
              f" — system in production mode.")
    store.close()
    return 0


def _cmd_alerts(cfg: Config, state: str) -> int:
    """Toggle alert output to SIEM (persisted in DB, picked up by running daemon)."""
    store = Store(cfg.get("storage.db_path"))
    store.connect()
    value = "1" if state == "on" else "0"
    store.set_meta("alerts_enabled", value)
    if state == "on":
        print(f"{_C_GREEN}Alert output ENABLED{_C_RESET}"
              f" — events will be sent to SIEM.")
    else:
        print(f"{_C_RED}Alert output DISABLED{_C_RESET}"
              f" — SIEM will NOT receive events.")
        print(f"{_C_DIM}  Detection and baseline learning continue internally.{_C_RESET}")
    store.close()
    return 0


def _cmd_ntfy(cfg: Config, state: str) -> int:
    """Toggle ntfy push notifications independently of SIEM output."""
    store = Store(cfg.get("storage.db_path"))
    store.connect()
    value = "1" if state == "on" else "0"
    store.set_meta("ntfy_enabled", value)
    if state == "on":
        print(f"{_C_GREEN}ntfy push notifications ENABLED{_C_RESET}")
    else:
        print(f"{_C_RED}ntfy push notifications DISABLED{_C_RESET}")
        print(f"{_C_DIM}  SIEM output and detection are unaffected.{_C_RESET}")
    store.close()
    return 0


# ── Log formatting + tailing ─────────────────────────────────────────────────

def _fmt_log_line(raw: str) -> str | None:
    """Parse one JSON alert line and return a coloured string, or None."""
    import json
    try:
        e = json.loads(raw)
    except json.JSONDecodeError:
        return raw  # pass through non-JSON lines unchanged

    ts      = e.get("timestamp", "")
    level   = e.get("habitd_level", "?").lower()
    parent  = e.get("parent_executable_path") or e.get("parent_name") or "(unknown)"
    exe     = e.get("executable_path", "?")
    layer   = e.get("detection_layer", "")
    reasons = e.get("reasons", [])

    lc = _LEVEL_COLOR.get(level, _C_RESET)

    line = (
        f"{_C_GREEN}{ts}{_C_RESET}  "
        f"{lc}[{level}]{_C_RESET}  "
        f"{_C_PATH}{parent}{_C_RESET} → {_C_PATH}{exe}{_C_RESET}  "
        f"{_C_DIM}({layer}){_C_RESET}"
    )

    # show reasons only for high / medium
    if reasons and level in ("high", "medium"):
        joined = ", ".join(reasons)
        line += f"\n{' '*27}{_C_DIM}↳ {joined}{_C_RESET}"

    return line


def _cmd_log(cfg: Config, lines: int) -> int:
    """Tail the alert log with pretty-printed coloured output. Ctrl-C to exit."""
    import subprocess

    # Show learning/alerts status hint.
    store = Store(cfg.get("storage.db_path"))
    store.connect()
    _print_learning_hint(store, cfg)
    store.close()

    log_path = cfg.get("alerting.json_log", "/var/log/habitd/alerts.json")
    if not os.path.exists(log_path):
        print(f"Alert log not found: {log_path}", file=sys.stderr)
        return 1

    # Print last N lines.
    try:
        result = subprocess.run(
            ["/usr/bin/tail", "-n", str(lines), log_path],
            capture_output=True, text=True,
        )
        for raw in result.stdout.splitlines():
            formatted = _fmt_log_line(raw)
            if formatted:
                print(formatted)
    except Exception:
        pass

    # Live follow.
    try:
        proc = subprocess.Popen(
            ["/usr/bin/tail", "-f", "-n", "0", log_path],
            stdout=subprocess.PIPE, text=True,
        )
        for raw in proc.stdout:
            formatted = _fmt_log_line(raw.rstrip("\n"))
            if formatted:
                print(formatted, flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
    return 0


def _cmd_flush(cfg: Config) -> int:
    """Force WAL checkpoint — flush pending writes to main DB file."""
    store = Store(cfg.get("storage.db_path"))
    store.connect()
    store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    print("WAL checkpoint complete.")
    store.close()
    return 0


# ── Interactive review ───────────────────────────────────────────────────────

def _getchar() -> str:
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ch


def _cmd_review_pending(cfg: Config) -> int:
    """Interactive review of all pending baseline tuples.

    y = confirm  n = skip  m = malicious  a = confirm all remaining  q = quit
    """
    store = Store(cfg.get("storage.db_path"))
    store.connect()

    # Show learning/alerts status hint.
    _print_learning_hint(store, cfg)

    rows = store.conn.execute(
        "SELECT id, parent_exe, exe, uid, count FROM baseline "
        "WHERE status='pending' ORDER BY count DESC"
    ).fetchall()

    if not rows:
        print("No pending tuples to review.")
        store.close()
        return 0

    total = len(rows)
    confirmed = skipped = malicious = 0

    print(f"{'─'*60}")
    print(f"  habitd — baseline review ({total} pending tuples)")
    print("  y=confirm  n=skip  m=malicious  a=confirm all  q=quit")
    print(f"{'─'*60}\n")

    for i, row in enumerate(rows, 1):
        parent = row["parent_exe"] or ""
        print(f"[{i}/{total}] x{row['count']:<4} uid={row['uid']:<5}  "
              f"{_path(parent)}  →  {_path(row['exe'])}")

        while True:
            try:
                sys.stdout.write("  > ")
                sys.stdout.flush()
                choice = _getchar().lower()
                print(choice)
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                store.close()
                return 1

            if choice == "y":
                store.conn.execute(
                    "UPDATE baseline SET status='confirmed' WHERE id=?", (row["id"],)
                )
                print("  ✓ confirmed")
                confirmed += 1
                break
            elif choice == "n":
                print("  – skipped")
                skipped += 1
                break
            elif choice == "m":
                store.conn.execute(
                    "UPDATE baseline SET status='malicious' WHERE id=?", (row["id"],)
                )
                print("  ✗ marked malicious")
                malicious += 1
                break
            elif choice == "a":
                remaining = len(rows) - i + 1
                sys.stdout.write(
                    f"{_C_RED}  ⚠ Confirm ALL {remaining} remaining tuples? (y/n) {_C_RESET}")
                sys.stdout.flush()
                confirm = _getchar().lower()
                print(confirm)
                if confirm != "y":
                    print("  – cancelled")
                    continue   # re-prompt for this tuple
                ids = [row["id"]] + [r["id"] for r in rows[i:]]
                store.conn.executemany(
                    "UPDATE baseline SET status='confirmed' WHERE id=?",
                    [(rid,) for rid in ids],
                )
                confirmed += len(ids)
                print(f"  ✓ confirmed {len(ids)} tuples")
                print(f"\n{'─'*60}")
                print(f"  Done — confirmed: {confirmed}  skipped: {skipped}"
                      f"  malicious: {malicious}")
                print(f"{'─'*60}")
                store.close()
                return 0
            elif choice == "q":
                print(f"\n{'─'*60}")
                print(f"  Quit — confirmed: {confirmed}  skipped: {skipped}"
                      f"  malicious: {malicious}")
                print(f"{'─'*60}")
                store.close()
                return 0
            else:
                print("  ? y / n / m / a / q")

    print(f"\n{'─'*60}")
    print(f"  Done — confirmed: {confirmed}  skipped: {skipped}"
          f"  malicious: {malicious}")
    print(f"{'─'*60}")
    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
