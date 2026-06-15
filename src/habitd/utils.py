"""Shared utilities."""

from __future__ import annotations

# ANSI 256-color — muted blue-grey for filesystem paths in terminal output.
_BLUE = "\033[38;5;110m"
_RESET = "\033[0m"


def path(p: str) -> str:
    """Render a filesystem path in muted blue for terminal output."""
    return f"{_BLUE}{p}{_RESET}" if p else f"{_BLUE}(unknown){_RESET}"
