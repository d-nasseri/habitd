"""habitd — behavioral process-habit detection daemon.

V0.1 scope: learn parent->child->user->path tuples from auditd execve events,
alert on previously unseen relationships, emit Wazuh-compatible JSON.
"""

__version__ = "0.1.0"
