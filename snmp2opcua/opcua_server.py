"""Server mode: the gateway hosts its own OPC UA server (asyncua).

Address space (namespace index is usually 2):

  Objects/SNMPTrapGateway                       ns=2;s=Gateway   (emits SnmpTrapEventType events)
    Status/  TrapsReceived, TrapsPublished, TrapsDropped, TrapsRejected, MalformedPackets, StartTime
    LastTrap/ SourceIP, Version, PduType, SecurityName, TrapOID, TrapName, Uptime, ReceivedAt, VarBindsJson, Json
    RecentTrapsJson                             JSON array of the last N traps (newest first)
    Devices/<source-ip>/ TrapCount, LastTrapOID, LastTrapName, LastTrapTime, LastTrapJson

  Objects/<Channel>/<Device>/<Tag>              ns=2;s=Channel.Device.Tag   (SNMP-driver style trap tags)
    trap tags (Boolean, writable: write 0 to reset), table fields [n], EVENTS_COUNT (writable),
    EVENTS_001.., EVENTS_nnn_FLDCNT, EVENTS_nnn_mmm; tag groups ("Group.Tag") become folders
"""
from __future__ import annotations

import json
import logging
from collections import deque
from datetime import datetime, timezone

from asyncua import Server, ua

from .receiver import Stats
from .severity import SeverityMap
from .snmp_driver import OPCUA_TYPES, DeviceDef
from .trap import Trap

log = logging.getLogger("snmp2opcua.opcua_server")

# OPC UA built-in type -> data type name as shown in the window (server-style names)
KEPWARE_TYPE = {"Boolean": "Boolean", "String": "String", "Int32": "Long", "UInt32": "DWord", "UInt64": "QWord",
                "Float": "Float", "Double": "Double", "DateTime": "Date"}

S = ua.VariantType.String
U32 = ua.VariantType.UInt32
U64 = ua.VariantType.UInt64
DT = ua.VariantType.DateTime


class OpcUaServerPublisher:
    def __init__(self, cfg: dict, severity: SeverityMap, devices: list[DeviceDef] | None = None):
        self.cfg = cfg
        self.severity = severity
        self.devices_cfg = devices or []
        self.tag_nodes: dict[str, tuple[object, object]] = {}   # path -> (node, variant type)
        self.writable_paths: set[str] = set()
        self.extra_tags: list[tuple[str, str]] = []             # (path, data type), e.g. polling status
        self._folders: dict[str, object] = {}
        self._objects = None
        # writes to the gateway's own nodes are reported to the desktop window's Live data view
        self.observer = None
        self.node_paths: dict = {}                              # node -> "Gateway.LastTrap.TrapName"
        self.gw_catalog: dict[str, tuple[object, str]] = {}     # path -> (initial value, data type)
        self._pending: list[tuple[str, object, str]] = []
        self.engine = None                                      # set by the gateway (for client resets)
        self._reset_sub = None
        self.server: Server | None = None
        self.idx = 2
        self.recent: deque[dict] = deque(maxlen=int(cfg.get("recent_traps", 50)))
        self.devices: dict[str, dict] = {}
        self.max_devices = int(cfg.get("max_devices", 1000))
        self.evgen = None
        self.nodes: dict[str, object] = {}

    # ------------------------------------------------------------------ helpers
    def _nid(self, path: str) -> ua.NodeId:
        return ua.NodeId(path, self.idx)

    def _qn(self, name: str) -> ua.QualifiedName:
        return ua.QualifiedName(name, self.idx)

    async def _obj(self, parent, path: str, name: str):
        return await parent.add_object(self._nid(path), self._qn(name))

    async def _var(self, parent, path: str, name: str, value, vtype):
        node = await parent.add_variable(self._nid(f"{path}.{name}"), self._qn(name), value, varianttype=vtype)
        full = f"{path}.{name}"
        self.node_paths[node] = full
        self.gw_catalog[full] = (value, KEPWARE_TYPE.get(vtype.name, vtype.name))
        if self.server is not None:                    # created while running (a new trap source)
            self._pending.append((full, value, KEPWARE_TYPE.get(vtype.name, vtype.name)))
        return node

    async def _write(self, node, value, vtype):
        await node.write_value(value, vtype)
        path = self.node_paths.get(node)
        if path is not None:
            dtype = KEPWARE_TYPE.get(vtype.name, vtype.name)
            self.gw_catalog[path] = (value, dtype)
            if self.observer is not None:
                self._pending.append((path, value, dtype))

    def _flush(self) -> None:
        if self._pending and self.observer is not None:
            items, self._pending = self._pending, []
            try:
                self.observer(items)
            except Exception:
                log.debug("observer failed", exc_info=True)
        else:
            self._pending = []

    def catalog(self) -> list[tuple[str, object, str]]:
        """The gateway's own variables (Status, LastTrap, ...) with their current values."""
        return [(p, v, t) for p, (v, t) in self.gw_catalog.items()]

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        cfg = self.cfg
        server = Server()
        await server.init()
        server.set_endpoint(cfg["endpoint"])
        server.set_server_name(cfg.get("server_name", "SNMP Trap Gateway"))

        policies = []
        for name in cfg.get("security_policies") or ["NoSecurity"]:
            try:
                policies.append(getattr(ua.SecurityPolicyType, name))
            except AttributeError:
                raise ValueError(f"Unknown OPC UA security policy {name!r}") from None
        server.set_security_policy(policies)
        if cfg.get("certificate") and cfg.get("private_key"):
            await server.load_certificate(cfg["certificate"])
            await server.load_private_key(cfg["private_key"])
        elif any(p != ua.SecurityPolicyType.NoSecurity for p in policies):
            raise ValueError("Secure OPC UA policies need 'certificate' and 'private_key' in config")

        self.idx = await server.register_namespace(cfg.get("namespace", "urn:snmp2opcua:gateway"))
        objects = server.nodes.objects

        gw = await self._obj(objects, "Gateway", "SNMPTrapGateway")
        status = await self._obj(gw, "Gateway.Status", "Status")
        now = datetime.now(timezone.utc)
        n = self.nodes
        n["received"] = await self._var(status, "Gateway.Status", "TrapsReceived", 0, U64)
        n["published"] = await self._var(status, "Gateway.Status", "TrapsPublished", 0, U64)
        n["dropped"] = await self._var(status, "Gateway.Status", "TrapsDropped", 0, U64)
        n["rejected"] = await self._var(status, "Gateway.Status", "TrapsRejected", 0, U64)
        n["malformed"] = await self._var(status, "Gateway.Status", "MalformedPackets", 0, U64)
        n["started"] = await self._var(status, "Gateway.Status", "StartTime", now, DT)

        last = await self._obj(gw, "Gateway.LastTrap", "LastTrap")
        p = "Gateway.LastTrap"
        n["source_ip"] = await self._var(last, p, "SourceIP", "", S)
        n["version"] = await self._var(last, p, "Version", "", S)
        n["pdu"] = await self._var(last, p, "PduType", "", S)
        n["security_name"] = await self._var(last, p, "SecurityName", "", S)
        n["trap_oid"] = await self._var(last, p, "TrapOID", "", S)
        n["trap_name"] = await self._var(last, p, "TrapName", "", S)
        n["uptime"] = await self._var(last, p, "Uptime", 0, U32)
        n["received_at"] = await self._var(last, p, "ReceivedAt", now, DT)
        n["varbinds"] = await self._var(last, p, "VarBindsJson", "[]", S)
        n["json"] = await self._var(last, p, "Json", "{}", S)
        n["recent"] = await self._var(gw, "Gateway", "RecentTrapsJson", "[]", S)

        self.devices_folder = await gw.add_folder(self._nid("Gateway.Devices"), self._qn("Devices"))

        if cfg.get("events", True):
            etype = await server.create_custom_event_type(
                self.idx, "SnmpTrapEventType", ua.ObjectIds.BaseEventType,
                [("SourceIP", S), ("SnmpVersion", S), ("SecurityName", S), ("TrapOID", S), ("TrapName", S),
                 ("VarBindsJson", S)],
            )
            self.evgen = await server.get_event_generator(etype, gw)

        await self._build_driver_tree(objects)

        self.server = server
        await server.start()
        await self._watch_resets()
        log.info("OPC UA server running at %s (namespace index %d)", cfg["endpoint"], self.idx)

    async def _folder(self, path: str):
        if path in self._folders:
            return self._folders[path]
        parent_path, _, name = path.rpartition(".")
        parent = await self._folder(parent_path) if parent_path else self._objects
        node = await parent.add_folder(self._nid(path), self._qn(name))
        self._folders[path] = node
        return node

    async def _add_tag(self, path: str, data_type: str, writable: bool = False):
        parent_path, _, name = path.rpartition(".")
        parent = await self._folder(parent_path)
        vtype = getattr(ua.VariantType, OPCUA_TYPES[data_type])
        initial = {"Boolean": False, "String": "", "Int32": 0, "UInt32": 0, "Float": 0.0, "Double": 0.0,
                   "DateTime": datetime(1970, 1, 1, tzinfo=timezone.utc)}[OPCUA_TYPES[data_type]]
        node = await parent.add_variable(self._nid(path), self._qn(name), initial, varianttype=vtype)
        if writable:
            await node.set_writable()
            self.writable_paths.add(path)
        self.tag_nodes[path] = (node, vtype)
        return node, vtype

    async def _build_driver_tree(self, objects) -> None:
        """Channel -> Device -> Tag, with Kepware-style string NodeIds ns=<idx>;s=Channel.Device.Tag."""
        self._objects = objects
        for dev in self.devices_cfg:
            await self._folder(dev.path)
            for tag in dev.tags:
                await self._add_tag(dev.tag_path(tag), tag.data_type, tag.writable)
        for path, data_type in self.extra_tags:
            if path not in self.tag_nodes:
                await self._add_tag(path, data_type)
        if self.tag_nodes:
            log.info("Created %d tags for %d devices", len(self.tag_nodes), len(self.devices_cfg))

    async def _watch_resets(self) -> None:
        """Notice when an OPC UA client writes 0 to a trap tag or EVENTS_COUNT, to keep the engine in step."""
        writable = [(p, self.tag_nodes[p][0]) for p in sorted(self.writable_paths)]
        if not writable or self.server is None:
            return
        paths = {n.nodeid: p for p, n in writable}
        outer = self

        class Handler:
            def datachange_notification(self, node, val, data):
                if not val and outer.engine is not None:
                    outer.engine.reset(paths.get(node.nodeid, ""))

        try:
            self._reset_sub = await self.server.create_subscription(500, Handler())
            await self._reset_sub.subscribe_data_change([n for _, n in writable])
        except Exception:
            log.debug("Could not watch trap tag resets", exc_info=True)

    async def _apply_tag_updates(self, trap: Trap) -> None:
        await self.apply_updates(trap.tag_updates)

    async def apply_updates(self, updates) -> None:
        """Write tag updates; tags first seen now (e.g. a new remote radio) get their node created."""
        if self.server is None:
            return
        for u in updates:
            entry = self.tag_nodes.get(u.path)
            if entry is None:
                if u.value is None:
                    continue
                entry = await self._add_tag(u.path, u.data_type)
            node, vtype = entry
            if u.value is None:
                continue
            if u.op == "inc":
                try:
                    current = int(await node.read_value() or 0)
                except Exception:
                    current = 0
                await self._write(node, (current + 1) & 0xFFFFFFFF, vtype)
            else:
                value = u.value
                if vtype == ua.VariantType.UInt32:
                    value = int(value) & 0xFFFFFFFF
                elif vtype == ua.VariantType.Int32:
                    value = max(-2**31, min(2**31 - 1, int(value)))
                await self._write(node, value, vtype)

    async def stop(self) -> None:
        if self.server is not None:
            await self.server.stop()
            self.server = None

    # ------------------------------------------------------------------ publishing
    async def _device(self, ip: str) -> dict | None:
        key = ip.replace(":", "_").replace("%", "_")
        dev = self.devices.get(key)
        if dev is not None:
            return dev
        if len(self.devices) >= self.max_devices:
            return None
        path = f"Gateway.Devices.{key}"
        obj = await self._obj(self.devices_folder, path, key)
        dev = {
            "count": 0,
            "count_node": await self._var(obj, path, "TrapCount", 0, U64),
            "oid": await self._var(obj, path, "LastTrapOID", "", S),
            "name": await self._var(obj, path, "LastTrapName", "", S),
            "time": await self._var(obj, path, "LastTrapTime", datetime.now(timezone.utc), DT),
            "json": await self._var(obj, path, "LastTrapJson", "{}", S),
        }
        self.devices[key] = dev
        log.info("New device node %s", path)
        return dev

    async def publish(self, trap: Trap) -> None:
        await self._apply_tag_updates(trap)
        n = self.nodes
        trap_json = trap.to_json()
        varbinds_json = trap.varbinds_json()

        await self._write(n["source_ip"], trap.source_ip, S)
        await self._write(n["version"], trap.version, S)
        await self._write(n["pdu"], trap.pdu, S)
        await self._write(n["security_name"], trap.security_name or "", S)
        await self._write(n["trap_oid"], trap.trap_oid, S)
        await self._write(n["trap_name"], trap.trap_name, S)
        await self._write(n["uptime"], (trap.uptime or 0) & 0xFFFFFFFF, U32)
        await self._write(n["received_at"], trap.received_at, DT)
        await self._write(n["varbinds"], varbinds_json, S)
        await self._write(n["json"], trap_json, S)  # written last: one atomic snapshot of the trap

        self.recent.appendleft(trap.to_dict())
        await self._write(n["recent"], json.dumps(list(self.recent), default=str, ensure_ascii=False), S)

        dev = await self._device(trap.source_ip)
        if dev is not None:
            dev["count"] += 1
            await self._write(dev["count_node"], dev["count"], U64)
            await self._write(dev["oid"], trap.trap_oid, S)
            await self._write(dev["name"], trap.trap_name, S)
            await self._write(dev["time"], trap.received_at, DT)
            await self._write(dev["json"], trap_json, S)

        if self.evgen is not None:
            ev = self.evgen.event
            ev.Severity = self.severity.for_trap(trap)
            ev.SourceName = trap.source_ip
            ev.SourceIP = trap.source_ip
            ev.SnmpVersion = trap.version
            ev.SecurityName = trap.security_name or ""
            ev.TrapOID = trap.trap_oid
            ev.TrapName = trap.trap_name
            ev.VarBindsJson = varbinds_json
            await self.evgen.trigger(message=trap.summary())
        self._flush()

    def diagnostics(self) -> dict:
        return {"kind": "server", "endpoint": self.cfg["endpoint"], "running": self.server is not None,
                "namespace_index": self.idx, "devices": len(self.devices), "max_devices": self.max_devices,
                "events": self.evgen is not None, "trap_tags": len(self.tag_nodes)}

    async def update_status(self, stats: Stats) -> None:
        if self.server is None:
            return
        n = self.nodes
        await self._write(n["received"], stats.received, U64)
        await self._write(n["published"], stats.published, U64)
        await self._write(n["dropped"], stats.dropped, U64)
        await self._write(n["rejected"], stats.rejected, U64)
        await self._write(n["malformed"], stats.malformed, U64)
        self._flush()
