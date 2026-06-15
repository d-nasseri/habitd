"""Sources sub-package: pluggable event producers.

Every source yields ExecEvent objects. The daemon does not know or care
whether they came from tailing audit.log or from an audisp plugin pushing
to stdin. Swapping the source is a config change, not a code change.
"""

from .base import EventSource, get_source

__all__ = ["EventSource", "get_source"]
