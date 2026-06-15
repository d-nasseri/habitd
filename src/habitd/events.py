"""Canonical event model.

Every event source (logparse, audisp, later eBPF) MUST emit this shape.
The rest of habitd never touches raw audit records — only ExecEvent.
This is the contract that lets the source be swapped without touching
detection, baseline, or alerting code.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ExecEvent:
    """A single process execution, normalized from an auditd execve record.

    V0.1 uses exe + parent_exe + uid as the baseline key. Args are captured
    but deliberately NOT used for detection yet (normalization is the hard
    part — deferred per roadmap).
    """

    timestamp: float          # epoch seconds (from the audit record, not wall clock)
    pid: int
    ppid: int
    uid: int                  # numeric uid; resolve to name only for display
    exe: str                  # full executable path, e.g. /usr/bin/python3.11
    comm: str                 # short process name, e.g. python3
    parent_exe: str           # full path of the parent's executable
    parent_comm: str          # short name of the parent
    cwd: str = ""             # working dir, if the source provides it
    args: tuple[str, ...] = field(default_factory=tuple)  # captured, unused in V0.1
    audit_id: str = ""        # original audit event id (e.g. "1717590000.123:456")

    # --- Baseline key ---------------------------------------------------------
    # The tuple that defines "have we seen this behavior before".
    # V0.1: parent_exe -> exe -> uid. Path-based, not comm-based, because
    # process names are trivially spoofable (cp /bin/bash /tmp/systemd).
    def baseline_key(self) -> tuple[str, str, int]:
        return (self.parent_exe, self.exe, self.uid)
