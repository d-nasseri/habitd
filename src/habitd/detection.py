"""Detection engine.

Two layers, per design:
  Layer 1 — static rules: high-confidence known-bad patterns, active from
            event one, no learning required. Signals, not verdicts.
  Layer 2 — learned baseline: is this (parent_exe, exe, uid) tuple known for
            THIS system? Unknown => anomaly.

A Verdict carries the reasons and the layer that fired. Severity is assigned
by the alert engine using the reason codes, not by string-matching reason text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple

from .events import ExecEvent

# Paths from which execution is intrinsically suspicious regardless of baseline.
# These fire hardcoded, independent of what the baseline has learned.
SUSPICIOUS_EXEC_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")


# --- Reason codes -------------------------------------------------------- #
# These are the stable identifiers downstream consumers (severity, Wazuh
# filters, dashboards) match against. The human-readable message can change
# without breaking any logic.

class Reason(NamedTuple):
    """A single reason a verdict was reached.

    Use `code` for any programmatic check (severity, SIEM filtering, tests).
    Use `message` only for human-facing text.

    The string form is "code: message" — preserves the documented Wazuh
    schema while giving structured access internally.
    """
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


# Stable reason code constants (grep-able, autocomplete-friendly).
R_SUSPICIOUS_PATH       = "static_rule.suspicious_path"
R_LAYER2_UNSEEN         = "layer2.parent_child_unseen"
R_KNOWN_MALICIOUS       = "ioc.matches_known_malicious"
R_PARENT_UNRESOLVED     = "context.parent_unresolved"
R_INPLACE_EXECVE        = "static_rule.inplace_execve"  # reserved for #3-revised
# Per-StaticRule codes are generated as "static_rule.{rule.name}".


# --- Verdict ------------------------------------------------------------- #

@dataclass(slots=True)
class Verdict:
    anomalous: bool
    layer: str = ""                       # primary: layer1_static | layer2_baseline | ""
    secondary_layer: str = ""             # set when both layers fire — for analytics
    reasons: list[Reason] = field(default_factory=list)

    def merge(self, other: "Verdict") -> "Verdict":
        """Combine two verdicts.

        Priority order: layer1_static is primary if both fire (it's the
        higher-confidence signal). The other layer is recorded as secondary
        so 'how often does Layer 2 also fire on a Layer 1 hit' is queryable.
        """
        if not other.anomalous:
            return self
        if not self.anomalous:
            return other
        return Verdict(
            anomalous=True,
            layer=self.layer,
            secondary_layer=other.layer,
            reasons=self.reasons + other.reasons,
        )

    def has_code(self, code: str) -> bool:
        """True if any reason carries this code."""
        return any(r.code == code for r in self.reasons)


# --- Layer 1 ------------------------------------------------------------- #

@dataclass(slots=True, frozen=True)
class StaticRule:
    name: str
    child: str | None
    parent: str | None
    reason: str
    uid: int | None = None

    def matches(self, ev: ExecEvent) -> bool:
        if self.child is not None and not re.search(self.child, ev.exe):
            return False
        if self.parent is not None and self.parent != ev.parent_comm:
            return False
        if self.uid is not None and self.uid != ev.uid:
            return False
        return True


# Seed rules. Tuple = immutable, no mutable-default footgun.
# Extend via the `rules=` parameter of check_static (e.g. from config).
DEFAULT_RULES: tuple[StaticRule, ...] = (
    StaticRule("shell_from_webserver", r"/(ba|da|z|k)?sh$", "nginx",
               "shell spawned by web server"),
    StaticRule("shell_from_webserver_apache", r"/(ba|da|z|k)?sh$", "apache2",
               "shell spawned by web server"),
    StaticRule("interpreter_from_sshd", r"/(python3|perl|ruby)$", "sshd",
               "interpreter spawned directly by sshd"),
    StaticRule("compiler_from_webserver", r"/(gcc|cc|clang)$", "nginx",
               "compiler invoked by web server"),
    StaticRule("compiler_from_webserver_apache", r"/(gcc|cc|clang)$", "apache2",
               "compiler invoked by web server"),
    StaticRule("service_user_shell", r"/(ba|da|z|k)?sh$", None,
               "shell spawned as service user (www-data/uid=33)", uid=33),
    StaticRule("service_user_interpreter", r"/(python3|perl|ruby|php)$", None,
               "interpreter spawned as service user (www-data/uid=33)", uid=33),
)


def check_static(
    ev: ExecEvent,
    rules: tuple[StaticRule, ...] | None = None,
) -> Verdict:
    """Layer 1 — static rule evaluation.

    `rules=None` falls back to DEFAULT_RULES. Pass a custom tuple to override
    (e.g. from runtime-loaded config). The default is a tuple — no mutable-
    default footgun.
    """
    if rules is None:
        rules = DEFAULT_RULES

    reasons: list[Reason] = []

    # Path-based: execution from a writable/temp directory.
    if any(ev.exe.startswith(d) for d in SUSPICIOUS_EXEC_DIRS):
        reasons.append(Reason(
            R_SUSPICIOUS_PATH,
            f"execution from {ev.exe}",
        ))

    for rule in rules:
        if rule.matches(ev):
            reasons.append(Reason(
                f"static_rule.{rule.name}",
                rule.reason,
            ))

    if not reasons:
        return Verdict(anomalous=False)
    return Verdict(anomalous=True, layer="layer1_static", reasons=reasons)


# --- Layer 2 ------------------------------------------------------------- #

def check_baseline(ev: ExecEvent, seen: bool) -> Verdict:
    """`seen` = the store already has this baseline tuple confirmed/known.

    The store lookup is done by the caller (daemon) to keep this function
    pure and trivially testable.
    """
    if seen:
        return Verdict(anomalous=False)
    return Verdict(
        anomalous=True,
        layer="layer2_baseline",
        reasons=[Reason(R_LAYER2_UNSEEN, "parent_child_relationship_never_seen")],
    )


# --- Convenience constructors (used by daemon for non-detection reasons) - #

def parent_unresolved_verdict() -> Verdict:
    """Verdict generated when parent_exe could not be resolved.

    Not a real anomaly — a data-quality signal. Severity engine downgrades it.
    """
    return Verdict(
        anomalous=True,
        layer="layer2_baseline",
        reasons=[Reason(R_PARENT_UNRESOLVED, "parent_exe could not be resolved (process pre-existed daemon)")],
    )


def known_malicious_verdict() -> Verdict:
    """Verdict for a tuple flagged as IOC by an admin."""
    return Verdict(
        anomalous=True,
        layer="layer2_baseline",
        reasons=[Reason(R_KNOWN_MALICIOUS, "matches admin-flagged IOC tuple")],
    )


def inplace_execve_verdict(reason_detail: str = "") -> Verdict:
    """Verdict for in-place execve detection.

    Same process descriptor (PID + start_time) but exe path changed — the
    process replaced its own image without forking. Suspicious in long-running
    daemons; expected for service-manager re-execs (whitelist via config).
    """
    msg = "process performed execve in-place (image swap without fork)"
    if reason_detail:
        msg = f"{msg} — {reason_detail}"
    return Verdict(
        anomalous=True,
        layer="layer1_static",
        reasons=[Reason(R_INPLACE_EXECVE, msg)],
    )
