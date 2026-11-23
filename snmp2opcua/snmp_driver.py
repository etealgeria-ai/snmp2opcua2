"""Trap tags in the style of the KEPServerEX / TOP Server SNMP driver.

Configuration is a Channel -> Device -> Tag tree. A device is matched by the source
address of incoming traps and has the driver's trap settings: SNMP version (1, 2c, 3,
one v3 user per device), trap port and protocol, Custom Community, Number of Events,
Number of Fields and Extended ASCII.

Tag addresses (from the driver's "Trap Tags" help):

    TRAP_V1:.1.3.6.1.2.1.11:Gx             SNMPv1 generic trap x (0 coldStart, 1 warmStart,
                                           2 linkDown, 3 linkUp, 4 authenticationFailure,
                                           5 egpNeighborLoss); all generic traps share this OID
    TRAP_V1:<enterprise>:G6:Sx             SNMPv1 enterprise-specific trap x
    TRAP_V2C:<trap OID>                    SNMPv2c/v3 trap or inform (snmpTrapOID.0)
    ...:Px                                 only traps whose ifIndex varbind equals port x
    ...[n]                                 table field n of the trap message:
        [1] local timestamp  [2] enterprise OID  [3] generic trap  [4] specific trap
        [5] sysUpTime (timeticks)  [6] number of varbinds  [7] first varbind OID
        [8] first varbind value  [9]... following varbinds (OID, value, OID, value, ...)

A base tag (no [n]) is a Boolean that switches to 1 when the trap arrives; clients write 0
to reset it. Every device also gets the trap events queue: EVENTS_COUNT (increments per
trap; writable to reset), EVENTS_001..EVENTS_<Number of Events> (newest first, the whole
message as a semicolon-delimited string), EVENTS_nnn_FLDCNT and EVENTS_nnn_001.. fields.

The driver help documents the table fields but not the exact field layout of the events
queue messages, so EVENTS_nnn uses the same order as the table fields.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from .trap import Trap
from .usm import UsmUser

log = logging.getLogger("snmp2opcua.snmp_driver")

V1_GENERIC_OID = "1.3.6.1.2.1.11"
SNMP_TRAPS_OID = "1.3.6.1.6.3.1.1.5"
SNMP_TRAP_ENTERPRISE_0 = "1.3.6.1.6.3.1.1.4.3.0"
IFINDEX_OID = "1.3.6.1.2.1.2.2.1.1"
GENERIC_NAMES = ["coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss"]
AUTO_TRAPS = ["coldStart", "warmStart", "linkUp", "linkDown"]     # driver profiles: Ethernet Switch, Other Device
AUTO_TABLE_FIELDS = 20
MAX_TABLE_INDEX = 6 + 2 * 64

# Kepware data type name -> OPC UA built-in type
OPCUA_TYPES = {"Boolean": "Boolean", "String": "String", "Long": "Int32", "DWord": "UInt32",
               "Float": "Float", "Double": "Double", "Date": "DateTime"}
DATA_TYPES = set(OPCUA_TYPES)
POLL_TYPES = ("Boolean", "Long", "DWord", "Float", "Double", "String")
INITIAL = {"Boolean": False, "String": "", "Long": 0, "DWord": 0, "Float": 0.0, "Double": 0.0, "Date": None}
MIN_RATE_MS, MAX_RATE_MS = 10, 49 * 24 * 3600 * 1000

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _\-]*$")
_TRAP_ADDR = re.compile(r"^(TRAP_V1|TRAP_V2C):\.?([0-9]+(?:\.[0-9]+)+)((?::[A-Za-z][0-9]+)*)(?:\[([0-9]+)\])?$",
                        re.IGNORECASE)
_EVENTS_ADDR = re.compile(r"^EVENTS_(?:(COUNT)|([0-9]{3})(?:_(FLDCNT|[0-9]{3}))?)$", re.IGNORECASE)
_OID_ADDR = re.compile(r"^\.?([0-9]+(?:\.[0-9]+)+)$")


class DriverConfigError(ValueError):
    """Invalid channel/device/tag configuration (message says what to change)."""


class AddressError(DriverConfigError):
    pass


# --------------------------------------------------------------------------
# Addresses
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class TrapAddress:
    kind: str                 # "TRAP_V1" or "TRAP_V2C"
    oid: str
    generic: int | None = None
    specific: int | None = None
    port: int | None = None
    index: int | None = None  # table field [n]

    @property
    def default_type(self) -> str:
        if self.index is None:
            return "Boolean"
        return {1: "String", 2: "String", 3: "Long", 4: "Long", 5: "DWord", 6: "Long"}.get(self.index, "String")

    @property
    def writable(self) -> bool:
        return self.index is None        # base tags reset by writing 0

    def text(self) -> str:
        s = f"{self.kind}:.{self.oid}"
        if self.generic is not None:
            s += f":G{self.generic}"
        if self.specific is not None:
            s += f":S{self.specific}"
        if self.port is not None:
            s += f":P{self.port}"
        if self.index is not None:
            s += f"[{self.index}]"
        return s


@dataclass(frozen=True)
class EventsAddress:
    event: int | None         # None for EVENTS_COUNT
    field_no: int | None = None   # None: whole message; 0: FLDCNT; n: field n

    @property
    def default_type(self) -> str:
        if self.event is None:
            return "DWord"
        return "Long" if self.field_no == 0 else "String"

    @property
    def writable(self) -> bool:
        return self.event is None        # EVENTS_COUNT resets when written

    def text(self) -> str:
        if self.event is None:
            return "EVENTS_COUNT"
        s = f"EVENTS_{self.event:03d}"
        if self.field_no == 0:
            s += "_FLDCNT"
        elif self.field_no is not None:
            s += f"_{self.field_no:03d}"
        return s


@dataclass(frozen=True)
class PollAddress:
    """A polled OID (SNMP GET), like the driver's plain OID addresses."""
    oid: str
    default_type: str = "String"
    writable: bool = False

    def text(self) -> str:
        return f".{self.oid}"


def parse_address(text: str) -> TrapAddress | EventsAddress | PollAddress:
    s = (text or "").strip()
    m = _OID_ADDR.match(s)
    if m:
        oid = m.group(1)
        if any(int(a) > 4294967295 for a in oid.split(".")):
            raise AddressError(f"Invalid address '{text}': OID sub-identifiers must be within 0 to 4294967295")
        return PollAddress(oid)
    m = _EVENTS_ADDR.match(s)
    if m:
        if m.group(1):
            return EventsAddress(None)
        event = int(m.group(2))
        sub = (m.group(3) or "").upper()
        if event < 1:
            raise AddressError(f"Invalid address '{text}': event numbers start at 001")
        if not sub:
            return EventsAddress(event)
        if sub == "FLDCNT":
            return EventsAddress(event, 0)
        if int(sub) < 1:
            raise AddressError(f"Invalid address '{text}': field numbers start at 001")
        return EventsAddress(event, int(sub))

    m = _TRAP_ADDR.match(s)
    if not m:
        raise AddressError(f"Invalid address '{text}'. Use TRAP_V1:<OID>:Gx[:Sx][:Px][n], "
                           f"TRAP_V2C:<OID>[:Px][n] or an EVENTS_ address.")
    kind = m.group(1).upper()
    oid = m.group(2)
    if any(int(a) > 4294967295 for a in oid.split(".")):
        raise AddressError(f"Invalid address '{text}': OID sub-identifiers must be within 0 to 4294967295")
    mods: dict[str, int] = {}
    for part in filter(None, m.group(3).split(":")):
        key, val = part[0].upper(), int(part[1:])
        if key not in "GSP":
            raise AddressError(f"Invalid address '{text}': unknown field ':{part}' (use :G, :S or :P)")
        if key in mods:
            raise AddressError(f"Invalid address '{text}': ':{key}' given twice")
        mods[key] = val
    index = int(m.group(4)) if m.group(4) else None
    if index is not None and not 1 <= index <= MAX_TABLE_INDEX:
        raise AddressError(f"Invalid address '{text}': table index must be 1 to {MAX_TABLE_INDEX}")
    port = mods.get("P")
    if port is not None and port < 1:
        raise AddressError(f"Invalid address '{text}': port must be 1 or higher")

    if kind == "TRAP_V1":
        if "G" not in mods:
            raise AddressError(f"Invalid address '{text}': SNMPv1 trap addresses need :Gx (generic trap 0-6)")
        g = mods["G"]
        if not 0 <= g <= 6:
            raise AddressError(f"Invalid address '{text}': generic trap must be 0 to 6")
        if g < 6:
            if "S" in mods:
                raise AddressError(f"Invalid address '{text}': :S is only used with :G6 (enterprise traps)")
            if oid != V1_GENERIC_OID:
                raise AddressError(f"Invalid address '{text}': generic traps use the OID .{V1_GENERIC_OID}")
            return TrapAddress(kind, oid, g, None, port, index)
        if "S" not in mods:
            raise AddressError(f"Invalid address '{text}': enterprise traps (:G6) need :Sx (specific trap number)")
        return TrapAddress(kind, oid, 6, mods["S"], port, index)

    if "G" in mods or "S" in mods:
        raise AddressError(f"Invalid address '{text}': SNMPv2c addresses don't use :G or :S; give the trap OID")
    if oid == f"{SNMP_TRAPS_OID}.6":
        raise AddressError(f"Invalid address '{text}': egpNeighborLoss is not implemented for SNMPv2c")
    return TrapAddress(kind, oid, None, None, port, index)


# --------------------------------------------------------------------------
# Configuration model
# --------------------------------------------------------------------------
@dataclass
class TagDef:
    name: str                 # may contain dots for tag groups: "Group1.Tag1"
    address: TrapAddress | EventsAddress | PollAddress
    data_type: str
    description: str = ""
    auto: bool = False

    @property
    def writable(self) -> bool:
        return self.address.writable


@dataclass
class PollConfig:
    """SNMP polling of the device (GET / table walks)."""
    enabled: bool = True
    community: str = "public"
    version: str = "2c"               # "1" or "2c"
    port: int = 161
    scan_rate_ms: int = 10000
    timeout_ms: int = 2000
    retries: int = 1
    max_repetitions: int = 20
    ge_orbit_remotes: bool = False    # read RSSI/IP of remote radios from a GE MDS Orbit master
    rssi_warning_dbm: int | None = None
    remote_tags: int = 255            # fixed tags Remote1..RemoteN (RSSI), 0 = none
    remote_tag_prefix: str = "Remote"
    remote_slots: dict[int, str] = field(default_factory=dict)   # pinned: slot -> MAC or IP


@dataclass
class DeviceDef:
    channel: str
    name: str
    host: str                         # IP address or host name (device ID)
    snmp_version: str = "2c"          # "1", "2c" or "3"
    trap_enabled: bool = True
    port: int = 162
    protocol: str = "UDP"
    community: str = ""               # Custom Community; empty accepts any (or none)
    number_of_events: int = 10
    number_of_fields: int = 10
    extended_ascii: bool = False
    v3_user: UsmUser | None = None
    poll: PollConfig | None = None
    tags: list[TagDef] = field(default_factory=list)

    @property
    def path(self) -> str:
        return f"{self.channel}.{self.name}"

    def tag_path(self, tag: TagDef | str) -> str:
        return f"{self.path}.{tag if isinstance(tag, str) else tag.name}"


def _check_name(kind: str, name: object, allow_groups: bool = False) -> str:
    name = str(name or "").strip()
    parts = name.split(".") if allow_groups else [name]
    for p in parts:
        if not p or not _NAME.match(p):
            raise DriverConfigError(
                f"The {kind} name '{name}' is invalid. Use letters, digits, spaces, '_' or '-'; names cannot be "
                f"empty, contain periods{' (except between tag group names)' if allow_groups else ''} or double "
                f"quotes, or start with an underscore.")
    return name


def _int(value, lo: int, hi: int, what: str, default: int) -> int:
    if value is None:
        return default
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise DriverConfigError(f"{what} must be a whole number from {lo} to {hi}") from None
    if not lo <= v <= hi:
        raise DriverConfigError(f"{what} must be within the range of {lo} to {hi}")
    return v


def make_tag(name: str, address: str, data_type: str | None = None, description: str = "",
             device: str = "", auto: bool = False) -> TagDef:
    where = f" (device {device})" if device else ""
    name = _check_name("tag", name, allow_groups=True)
    try:
        addr = parse_address(address)
    except AddressError as exc:
        raise DriverConfigError(f"Tag {name}{where}: {exc}") from None
    dt = (data_type or "Default").strip()
    dt = {"bool": "Boolean", "boolean": "Boolean", "string": "String", "long": "Long", "dword": "DWord",
          "default": "Default"}.get(dt.lower(), dt)
    if dt == "Default":
        dt = addr.default_type
    if isinstance(addr, PollAddress):
        if dt not in POLL_TYPES:
            raise DriverConfigError(f"Tag {name}{where}: data type {dt} is not supported for polled OIDs; "
                                    f"use one of {', '.join(POLL_TYPES)}")
    elif dt not in (addr.default_type, "String"):
        raise DriverConfigError(f"Tag {name}{where}: data type {dt} is not valid for address {addr.text()}; "
                                f"use Default ({addr.default_type}) or String")
    return TagDef(name, addr, dt, description or "", auto)


def auto_tags(dev: DeviceDef) -> list[TagDef]:
    """Base tag + 20 table fields for coldStart, warmStart, linkUp and linkDown, plus the events queue."""
    out = []
    for name in AUTO_TRAPS:
        g = GENERIC_NAMES.index(name)
        base = f"TRAP_V1:.{V1_GENERIC_OID}:G{g}" if dev.snmp_version == "1" else f"TRAP_V2C:.{SNMP_TRAPS_OID}.{g + 1}"
        out.append(make_tag(name, base, auto=True))
        out += [make_tag(f"{name}_{i:03d}", f"{base}[{i}]", auto=True) for i in range(1, AUTO_TABLE_FIELDS + 1)]
    return out


def events_tags(dev: DeviceDef) -> list[TagDef]:
    out = [make_tag("EVENTS_COUNT", "EVENTS_COUNT", auto=True)]
    for e in range(1, dev.number_of_events + 1):
        out.append(make_tag(f"EVENTS_{e:03d}", f"EVENTS_{e:03d}", auto=True))
        out.append(make_tag(f"EVENTS_{e:03d}_FLDCNT", f"EVENTS_{e:03d}_FLDCNT", auto=True))
        out += [make_tag(f"EVENTS_{e:03d}_{f:03d}", f"EVENTS_{e:03d}_{f:03d}", auto=True)
                for f in range(1, dev.number_of_fields + 1)]
    return out


def build_devices(channels_cfg: list, base_dir=None, csv_loader=None, default_port: int = 162) -> list[DeviceDef]:
    """Validate the `channels:` config and return the devices (with auto-created tags)."""
    devices: list[DeviceDef] = []
    seen_channels: set[str] = set()
    for c in channels_cfg or []:
        if not isinstance(c, dict):
            raise DriverConfigError("Each entry under channels must be a mapping with a name and devices")
        ch = _check_name("channel", c.get("name"))
        if ch in seen_channels:
            raise DriverConfigError(f"The channel {ch} has already been added")
        seen_channels.add(ch)
        seen_devices: set[str] = set()
        for d in c.get("devices") or []:
            name = _check_name("device", d.get("name"))
            if name in seen_devices:
                raise DriverConfigError(f"The device {ch}.{name} has already been added")
            seen_devices.add(name)
            where = f"Device {ch}.{name}"
            host = str(d.get("ip") or d.get("host") or "").strip()
            if not host:
                raise DriverConfigError(f"{where}: set ip to the device's IP address or host name")
            version = str(d.get("snmp_version", "2c")).lower().lstrip("v")
            if version not in ("1", "2c", "3"):
                raise DriverConfigError(f"{where}: snmp_version must be 1, 2c or 3")
            t = d.get("trap") or {}
            protocol = str(t.get("protocol", "UDP")).upper()
            if protocol not in ("UDP", "TCP"):
                raise DriverConfigError(f"{where}: trap protocol must be UDP or TCP")
            community = str(t.get("community") or "")
            if len(community) > 256:
                raise DriverConfigError(f"{where}: Custom Community can be up to 256 characters")
            dev = DeviceDef(
                channel=ch, name=name, host=host, snmp_version=version,
                trap_enabled=bool(t.get("enabled", True)),
                port=_int(t.get("port"), 1, 65535, f"{where}: trap port", default_port),
                protocol=protocol, community=community,
                number_of_events=_int(t.get("number_of_events"), 1, 100, f"{where}: Number of Events", 10),
                number_of_fields=_int(t.get("number_of_fields"), 1, 20, f"{where}: Number of Fields", 10),
                extended_ascii=bool(t.get("extended_ascii", False)))
            if version == "3":
                v3 = d.get("v3") or {}
                if not v3.get("username"):
                    raise DriverConfigError(f"Unable to load username for device {ch}.{name}. "
                                            "Specify a username under v3 (SNMP V3 Security).")
                try:
                    dev.v3_user = UsmUser.create(str(v3["username"]), v3.get("auth_protocol"),
                                                 v3.get("auth_passphrase"), v3.get("priv_protocol"),
                                                 v3.get("priv_passphrase"))
                except ValueError as exc:
                    raise DriverConfigError(f"{where} SNMP V3 Security: {exc}") from None

            if d.get("polling") is not None:
                dev.poll = _poll_config(d["polling"], dev, where)

            tags: list[TagDef] = []
            names: set[str] = set()
            sources = list(d.get("tags") or [])
            if d.get("tags_csv") and csv_loader is not None:
                sources += csv_loader(d["tags_csv"], base_dir, f"{ch}.{name}")
            for tg in sources:
                if isinstance(tg, TagDef):
                    tag = tg
                else:
                    tag = make_tag(tg.get("name"), tg.get("address"), tg.get("data_type"),
                                   tg.get("description", ""), device=f"{ch}.{name}")
                if tag.name in names:
                    raise DriverConfigError(f"The tag {ch}.{name}.{tag.name} has already been added")
                if isinstance(tag.address, EventsAddress):
                    _check_events_range(tag, dev)
                if isinstance(tag.address, PollAddress) and dev.poll is None:
                    raise DriverConfigError(f"Tag {ch}.{name}.{tag.name} polls OID {tag.address.text()}, but the "
                                            f"device has no polling settings. Add polling: {{community: ...}}.")
                names.add(tag.name)
                tags.append(tag)
            generated = events_tags(dev) + (auto_tags(dev) if d.get("auto_create_tags", True) else [])
            for tag in generated:
                if tag.name not in names:          # a tag you defined yourself takes precedence
                    names.add(tag.name)
                    tags.append(tag)
            if dev.snmp_version == "1" and any(isinstance(t.address, TrapAddress) and t.address.kind == "TRAP_V2C"
                                               and not t.auto for t in tags):
                log.warning("%s uses SNMP version 1 but has TRAP_V2C tags; they will never update", where)
            dev.tags = tags
            devices.append(dev)
    return devices


def _rate(value, what: str, default: int) -> int:
    if value is None:
        return default
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise DriverConfigError(f"{what}: give the rate in milliseconds") from None
    if not MIN_RATE_MS <= v <= MAX_RATE_MS:
        raise DriverConfigError(f"{what}: the rate must be within the range of 10 milliseconds and 49 days.")
    return v


def _poll_config(p: dict, dev: DeviceDef, where: str) -> PollConfig:
    if not isinstance(p, dict):
        raise DriverConfigError(f"{where}: polling must be a mapping, e.g. {{community: public}}")
    given = p.get("snmp_version", dev.snmp_version if dev.snmp_version in ("1", "2c") else None)
    version = str(given or "").lower().lstrip("v")
    if version not in ("1", "2c"):
        raise DriverConfigError(f"{where}: polling supports SNMP version 1 or 2c; set polling.snmp_version")
    warn = p.get("rssi_warning_dbm")
    remote_tags = _int(p.get("remote_tags"), 0, 1000, f"{where}: remote_tags", 255)
    prefix = _check_name("remote tag prefix", p.get("remote_tag_prefix", "Remote"))
    slots: dict[int, str] = {}
    seen_ids: dict[str, int] = {}
    for k, v in (p.get("remote_slots") or {}).items():
        slot = _int(str(k).removeprefix(prefix), 1, max(remote_tags, 1), f"{where}: remote_slots key {k}", 1)
        if isinstance(v, (int, float)):
            raise DriverConfigError(f"{where}: remote_slots {k}: put the MAC address in quotes, e.g. "
                                    f"\"10:20:30:40:50:59\" (YAML reads all-digit MACs as numbers)")
        ident = normalize_remote_id(str(v))
        if ident is None:
            raise DriverConfigError(f"{where}: remote_slots {k}: {v!r} is not a MAC address (00:06:3D:12:34:56) "
                                    f"or an IP address")
        if ident in seen_ids:
            raise DriverConfigError(f"{where}: {v} is pinned to both {prefix}{seen_ids[ident]} and {prefix}{slot}")
        seen_ids[ident] = slot
        slots[slot] = ident
    return PollConfig(
        enabled=bool(p.get("enabled", True)),
        community=str(p.get("community", "public")),
        version=version,
        port=_int(p.get("port"), 1, 65535, f"{where}: polling port", 161),
        scan_rate_ms=_rate(p.get("scan_rate_ms"), f"{where}: polling scan_rate_ms", 10000),
        timeout_ms=_int(p.get("timeout_ms"), 50, 60000, f"{where}: polling timeout_ms", 2000),
        retries=_int(p.get("retries"), 0, 10, f"{where}: polling retries", 1),
        max_repetitions=_int(p.get("max_repetitions"), 1, 200, f"{where}: polling max_repetitions", 20),
        ge_orbit_remotes=bool(p.get("ge_orbit_remotes", False)),
        rssi_warning_dbm=None if warn is None else _int(warn, -200, 0, f"{where}: rssi_warning_dbm", -95),
        remote_tags=remote_tags, remote_tag_prefix=prefix, remote_slots=slots)


def normalize_remote_id(text: str) -> str | None:
    """A remote radio's MAC ('00:06:3D:12:34:56') or IP address, normalised; None if it's neither."""
    t = text.strip()
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        pass
    hexdigits = re.sub(r"[:\-. ]", "", t)
    if re.fullmatch(r"[0-9A-Fa-f]{12}", hexdigits):
        return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)).upper()
    return None


def _check_events_range(tag: TagDef, dev: DeviceDef) -> None:
    a = tag.address
    assert isinstance(a, EventsAddress)
    if a.event is not None and a.event > dev.number_of_events:
        raise DriverConfigError(f"Tag {dev.path}.{tag.name}: event {a.event:03d} is beyond Number of Events "
                                f"({dev.number_of_events})")
    if a.field_no and a.field_no > dev.number_of_fields:
        raise DriverConfigError(f"Tag {dev.path}.{tag.name}: field {a.field_no:03d} is beyond Number of Fields "
                                f"({dev.number_of_fields})")


# --------------------------------------------------------------------------
# Runtime
# --------------------------------------------------------------------------
@dataclass
class Update:
    path: str                 # "Channel.Device.Tag"
    value: object
    data_type: str            # Kepware type name
    op: str = "set"           # "set" or "inc" (EVENTS_COUNT)
    good: bool = True         # False when a table index is beyond the received message


@dataclass
class DeviceState:
    events: deque
    count: int = 0            # traps accepted (engine view; clients can reset EVENTS_COUNT in OPC UA)
    ignored: int = 0          # traps from this IP refused by the device's settings
    last_trap: datetime | None = None
    last_reason: str = ""
    resolved: str | None = None
    error: str = ""


def v2_to_v1_identity(trap: Trap) -> tuple[str, int, int]:
    """RFC 3584 3.2: (enterprise, generic, specific) for an SNMPv2 notification."""
    if trap.version == "v1":
        return trap.enterprise or "", trap.generic_trap or 0, trap.specific_trap or 0
    oid = trap.trap_oid
    ent_vb = next((v for v in trap.varbinds if v.oid == SNMP_TRAP_ENTERPRISE_0), None)
    if oid.startswith(SNMP_TRAPS_OID + ".") and oid.count(".") == SNMP_TRAPS_OID.count(".") + 1:
        g = int(oid.rsplit(".", 1)[1]) - 1
        if 0 <= g <= 5:
            return (str(ent_vb.value) if ent_vb else SNMP_TRAPS_OID), g, 0
    head, last = oid.rsplit(".", 1)
    if head.endswith(".0"):
        head = head[:-2]
    return head, 6, int(last)


class TrapTagEngine:
    def __init__(self, devices: list[DeviceDef], resolve=socket.gethostbyname):
        self.devices = devices
        self.state: dict[str, DeviceState] = {}
        self.by_ip: dict[str, list[DeviceDef]] = {}
        self.values: dict[str, tuple[object, bool, datetime | None]] = {}
        self.unmatched: dict[str, int] = {}
        for dev in devices:
            st = DeviceState(events=deque(maxlen=dev.number_of_events))
            self.state[dev.path] = st
            try:
                ip = str(ipaddress.ip_address(dev.host))
            except ValueError:
                try:
                    ip = resolve(dev.host)
                except OSError:
                    st.error = (f"Unable to resolve host address {dev.host} on device {dev.path} for trap "
                                f"processing. Verify the host name.")
                    log.warning(st.error)
                    continue
            st.resolved = ip
            self.by_ip.setdefault(ip, []).append(dev)
            for tag in dev.tags:
                self.values[dev.tag_path(tag)] = (self._initial(tag), True, None)

    @staticmethod
    def _initial(tag: TagDef):
        return INITIAL[tag.data_type]

    def set_values(self, updates: list[Update]) -> None:
        """Record values that came from polling (paths may be new, e.g. a newly seen remote radio)."""
        for u in updates:
            self.values[u.path] = (u.value, u.good, datetime.now())

    def all_tags(self) -> list[tuple[DeviceDef, TagDef]]:
        return [(d, t) for d in self.devices for t in d.tags]

    @staticmethod
    def _accepts(dev: DeviceDef, trap: Trap) -> str:
        """Empty string if this device takes the trap, otherwise the reason it doesn't."""
        want = {"1": "v1", "2c": "v2c", "3": "v3"}[dev.snmp_version]
        if trap.version != want:
            return f"device is set to SNMP version {dev.snmp_version} but the trap is {trap.version}"
        if want == "v3":
            if dev.v3_user is None or trap.security_name != dev.v3_user.name:
                return f"SNMPv3 user {trap.security_name!r} is not this device's user"
        elif dev.community and trap.community != dev.community:
            return "community does not match the device's Custom Community"
        return ""

    @staticmethod
    def matches(addr: TrapAddress, trap: Trap) -> bool:
        if addr.kind == "TRAP_V1":
            if trap.version != "v1":
                return False
            if addr.generic is not None and addr.generic < 6:
                if trap.generic_trap != addr.generic:
                    return False
            elif not (trap.generic_trap == 6 and trap.enterprise == addr.oid and trap.specific_trap == addr.specific):
                return False
        elif trap.version not in ("v2c", "v3") or trap.trap_oid != addr.oid:
            return False
        if addr.port is not None:
            ifindex = next((v.value for v in trap.varbinds if v.oid.startswith(IFINDEX_OID + ".")), None)
            return ifindex == addr.port
        return True

    @staticmethod
    def _text(vb, extended_ascii: bool) -> str:
        if vb.value is None:
            return ""
        if extended_ascii and vb.type == "Octet String" and vb.raw:
            return vb.raw.decode("latin-1")
        return str(vb.value)

    def table_fields(self, trap: Trap, dev: DeviceDef) -> list[tuple[object, str]]:
        enterprise, generic, specific = v2_to_v1_identity(trap)
        fields: list[tuple[object, str]] = [
            (trap.received_at.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], "String"),
            (enterprise, "String"), (generic, "Long"), (specific, "Long"),
            ((trap.uptime or 0) & 0xFFFFFFFF, "DWord"), (len(trap.varbinds), "Long")]
        for vb in trap.varbinds:
            fields += [(vb.oid, "String"), (self._text(vb, dev.extended_ascii), "String")]
        return fields

    def process(self, trap: Trap) -> list[Update]:
        ip = trap.source_ip
        try:
            src = ipaddress.ip_address(ip.split("%")[0])
            if isinstance(src, ipaddress.IPv6Address) and src.ipv4_mapped:
                ip = str(src.ipv4_mapped)
        except ValueError:
            pass
        devs = self.by_ip.get(ip)
        if not devs:
            self.unmatched[ip] = self.unmatched.get(ip, 0) + 1
            return []
        updates: list[Update] = []
        for dev in devs:
            st = self.state[dev.path]
            if not dev.trap_enabled:
                continue
            reason = self._accepts(dev, trap)
            if reason:
                st.ignored += 1
                st.last_reason = reason
                continue
            st.count += 1
            st.last_trap = trap.received_at
            fields = self.table_fields(trap, dev)
            updates += self._events(dev, st, fields)
            for tag in dev.tags:
                a = tag.address
                if not isinstance(a, TrapAddress) or not self.matches(a, trap):
                    continue
                if a.index is None:
                    updates.append(Update(dev.tag_path(tag), True, tag.data_type))
                elif a.index <= len(fields):
                    value, _ = fields[a.index - 1]
                    updates.append(Update(dev.tag_path(tag), self._as(value, tag.data_type), tag.data_type))
                else:     # beyond the end of this message's table
                    updates.append(Update(dev.tag_path(tag), self._initial(tag), tag.data_type, good=False))
        now = trap.received_at
        for u in updates:
            if u.op == "inc":
                old = self.values.get(u.path, (0, True, None))[0]
                self.values[u.path] = ((int(old) if isinstance(old, int) else 0) + 1, True, now)
            else:
                self.values[u.path] = (u.value, u.good, now)
        return updates

    @staticmethod
    def _as(value, data_type: str):
        if data_type == "String":
            return "" if value is None else str(value)
        return value

    def _events(self, dev: DeviceDef, st: DeviceState, fields: list) -> list[Update]:
        msg = [str(v) for v, _ in fields][: dev.number_of_fields]
        st.events.appendleft(msg)
        p = dev.path
        out = [Update(f"{p}.EVENTS_COUNT", 1, "DWord", op="inc")]
        for i, ev in enumerate(st.events, 1):
            out.append(Update(f"{p}.EVENTS_{i:03d}", ";".join(ev), "String"))
            out.append(Update(f"{p}.EVENTS_{i:03d}_FLDCNT", len(ev), "Long"))
            for f in range(1, dev.number_of_fields + 1):
                out.append(Update(f"{p}.EVENTS_{i:03d}_{f:03d}", ev[f - 1] if f <= len(ev) else "", "String"))
        return out

    def reset(self, path: str) -> None:
        """A client wrote 0 to a writable tag (base trap tag or EVENTS_COUNT)."""
        if path in self.values:
            old = self.values[path][0]
            self.values[path] = (False if isinstance(old, bool) else 0, True, datetime.now())
