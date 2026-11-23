"""Map traps to OPC UA event severity (1 = info ... 1000 = critical)."""
from __future__ import annotations

from .trap import Trap


class SeverityMap:
    """Rules keyed by trap name (``linkDown``) or OID prefix (``1.3.6.1.4.1.9``).

    Exact name matches win; otherwise the longest matching OID prefix applies.
    """

    def __init__(self, cfg: dict | None = None):
        cfg = cfg or {}
        self.default = self._clamp(cfg.get("default", 500))
        self.by_name: dict[str, int] = {}
        self.by_oid: list[tuple[str, int]] = []
        for key, value in (cfg.get("rules") or {}).items():
            key = str(key).strip(".")
            if key.replace(".", "").isdigit():
                self.by_oid.append((key, self._clamp(value)))
            else:
                self.by_name[key] = self._clamp(value)
        self.by_oid.sort(key=lambda kv: len(kv[0]), reverse=True)

    @staticmethod
    def _clamp(v) -> int:
        return max(1, min(1000, int(v)))

    def for_trap(self, trap: Trap) -> int:
        if trap.trap_name in self.by_name:
            return self.by_name[trap.trap_name]
        for prefix, sev in self.by_oid:
            if trap.trap_oid == prefix or trap.trap_oid.startswith(prefix + "."):
                return sev
        return self.default
