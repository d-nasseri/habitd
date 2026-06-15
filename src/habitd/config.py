"""Config loading. Thin wrapper over YAML with dotted-path access and defaults.

Intentionally minimal — no schema validation framework for V0.1. If a key is
missing, the default in DEFAULTS is used. Fail loud only on an unreadable file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "daemon": {"source": "logparse", "audit_key": "habitd_exec"},
    "storage": {"db_path": "/var/lib/habitd/baseline.db"},
    "learning": {"mode": "continuous", "initial_phase_hours": 168},
    "alerting": {
        "json_log": "/var/log/habitd/alerts.json",
        "syslog": False,
        "min_level": "informational",
    },
    "source_logparse": {"audit_log_path": "/var/log/audit/audit.log", "flush_timeout": 30},
    "source_audisp": {"enabled": False},
    "logging": {"level": "INFO", "file": "/var/log/habitd/habitd.log"},
}


class Config:
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        path = Path(path)
        raw = yaml.safe_load(path.read_text()) or {}
        merged = _deep_merge(DEFAULTS, raw)
        return cls(merged)

    @classmethod
    def defaults(cls) -> "Config":
        return cls(_deep_merge(DEFAULTS, {}))

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def __getitem__(self, dotted: str) -> Any:
        return self.get(dotted)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out
