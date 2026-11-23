"""Map traps to OPC UA event severity (1 = info ... 1000 = critical)."""
from __future__ import annotations

from .trap import Trap


class SeverityMap:
    """Rules keyed by trap name (``linkDown``) or OID prefix (``1.3.6.1.2.1.33``)."""

    def __init__(self, cfg: dict):
        self.default = int(cfg.get("default", 500))
        self.rules = list((cfg.get("rules") or {}).items())

    def for_trap(self, trap: Trap) -> int:
        for key, severity in self.rules:
            if trap.trap_name == key or trap.trap_oid == key or trap.trap_oid.startswith(key + "."):
                return int(severity)
        return self.default
