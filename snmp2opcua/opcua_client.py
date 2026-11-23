"""Client mode: write each trap into variables on an existing OPC UA server (SCADA, PLC, historian).

Configure which fields go to which NodeIds under ``opcua.client.nodes``. The data type of
each target node is read once at connect time and values are converted to match it.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime

from asyncua import Client, ua

from .receiver import Stats
from .severity import SeverityMap
from .trap import Trap

log = logging.getLogger("snmp2opcua.opcua_client")

FIELDS = {
    "trap_json": lambda t, s, c: t.to_json(),
    "varbinds_json": lambda t, s, c: t.varbinds_json(),
    "source_ip": lambda t, s, c: t.source_ip,
    "version": lambda t, s, c: t.version,
    "security_name": lambda t, s, c: t.security_name or "",
    "trap_oid": lambda t, s, c: t.trap_oid,
    "trap_name": lambda t, s, c: t.trap_name,
    "uptime": lambda t, s, c: t.uptime or 0,
    "received_at": lambda t, s, c: t.received_at,
    "severity": lambda t, s, c: s.for_trap(t),
    "trap_count": lambda t, s, c: c,
    "summary": lambda t, s, c: t.summary(),
}

INT_TYPES = {
    ua.VariantType.SByte, ua.VariantType.Byte, ua.VariantType.Int16, ua.VariantType.UInt16,
    ua.VariantType.Int32, ua.VariantType.UInt32, ua.VariantType.Int64, ua.VariantType.UInt64,
}
FLOAT_TYPES = {ua.VariantType.Float, ua.VariantType.Double}
# Status codes that mean "the connection/session is gone", so reconnect rather than skip
CONNECTION_HINTS = ("Session", "SecureChannel", "Connection", "NotConnected", "Timeout", "Shutdown")


def _convert(value, vtype):
    if vtype == ua.VariantType.String:
        return value.isoformat() if isinstance(value, datetime) else str(value)
    if vtype in INT_TYPES:
        return int(value.timestamp()) if isinstance(value, datetime) else int(value)
    if vtype in FLOAT_TYPES:
        return float(value.timestamp()) if isinstance(value, datetime) else float(value)
    if vtype == ua.VariantType.Boolean:
        return bool(value)
    return value


class OpcUaClientPublisher:
    def __init__(self, cfg: dict, severity: SeverityMap):
        self.cfg = cfg
        self.severity = severity
        self.client: Client | None = None
        self.targets: list[tuple[str, object, ua.VariantType]] = []
        self.count = 0
        self.delay = float(cfg.get("reconnect_delay", 5))
        self.connects = 0
        self.write_errors = 0
        self.last_error: str | None = None
        self.last_error_at: datetime | None = None
        unknown = set(cfg.get("nodes") or {}) - set(FIELDS)
        if unknown:
            raise ValueError(f"Unknown field(s) in opcua.client.nodes: {sorted(unknown)}; "
                             f"valid: {sorted(FIELDS)}")
        if not any((cfg.get("nodes") or {}).values()):
            raise ValueError("opcua.client.nodes must map at least one field to a NodeId")

    async def start(self) -> None:
        try:
            await self._connect()
        except Exception as exc:  # keep running; publish() retries
            self._note_error(f"connection: {exc}")
            log.error("Initial connection to %s failed: %s (will retry)", self.cfg["url"], exc)
            await self._disconnect()

    async def _connect(self) -> None:
        cfg = self.cfg
        client = Client(cfg["url"], timeout=float(cfg.get("timeout", 4)))
        user = cfg.get("username")
        password = cfg.get("password") or os.environ.get("OPCUA_PASSWORD")
        if user:
            client.set_user(user)
            if password:
                client.set_password(password)
        if cfg.get("security_string"):
            await client.set_security_string(cfg["security_string"])
        await client.connect()
        self.client = client
        targets = []
        for field_name, nodeid in (cfg.get("nodes") or {}).items():
            if not nodeid:
                continue
            node = client.get_node(nodeid)
            vtype = await node.read_data_type_as_variant_type()
            targets.append((field_name, node, vtype))
            log.debug("Mapped %s -> %s (%s)", field_name, nodeid, vtype.name)
        self.targets = targets
        self.connects += 1
        log.info("Connected to OPC UA server %s (%d target nodes)", cfg["url"], len(targets))

    async def _disconnect(self) -> None:
        if self.client is not None:
            try:
                await self.client.disconnect()
            except Exception:
                pass
        self.client = None
        self.targets = []

    async def publish(self, trap: Trap) -> None:
        count = self.count + 1
        while True:
            try:
                if self.client is None:
                    await self._connect()
                await self._write_all(trap, count)
                self.count = count
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._note_error(f"connection: {exc}")
                log.error("OPC UA write failed (%s); reconnecting in %gs", exc, self.delay)
                await self._disconnect()
                await asyncio.sleep(self.delay)

    async def _write_all(self, trap: Trap, count: int) -> None:
        for field_name, node, vtype in self.targets:
            value = _convert(FIELDS[field_name](trap, self.severity, count), vtype)
            try:
                await node.write_value(value, vtype)
            except ua.UaStatusCodeError as exc:
                if any(h in str(exc) for h in CONNECTION_HINTS):
                    raise
                # Server is reachable but refused this node (type, access rights...): skip it
                self.write_errors += 1
                self._note_error(f"write to {node.nodeid.to_string()} ({field_name}) rejected: {exc}")
                log.error("Write to %s (%s) rejected: %s", node.nodeid.to_string(), field_name, exc)

    def _note_error(self, text: str) -> None:
        self.last_error = text
        self.last_error_at = datetime.now()

    def diagnostics(self) -> dict:
        return {"kind": "client", "url": self.cfg["url"], "connected": self.client is not None,
                "targets": len(self.targets),
                "configured_nodes": len([v for v in (self.cfg.get("nodes") or {}).values() if v]),
                "connects": self.connects, "write_errors": self.write_errors, "written": self.count,
                "last_error": self.last_error,
                "last_error_at": self.last_error_at.strftime("%H:%M:%S") if self.last_error_at else None}

    async def update_status(self, stats: Stats) -> None:
        return None

    async def stop(self) -> None:
        await self._disconnect()
