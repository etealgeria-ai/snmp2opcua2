"""Parse SNMP v1 traps and v2c traps/informs into a normalized Trap object."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import ber
from .oids import SNMP_TRAP_OID_0, SNMP_TRAPS, SYS_UPTIME_0, OidResolver

PDU_GET_RESPONSE = 0xA2
PDU_TRAP_V1 = 0xA4
PDU_INFORM = 0xA6
PDU_TRAP_V2 = 0xA7

VERSIONS = {0: "v1", 1: "v2c", 3: "v3"}


class UnsupportedMessage(ValueError):
    """Valid SNMP, but not something this gateway handles (e.g. SNMPv3, GET)."""


@dataclass
class VarBind:
    oid: str
    name: str
    type: str
    value: object
    raw: bytes = field(default=b"", repr=False, compare=False)   # undecoded value, for data-type conversion

    def as_dict(self) -> dict:
        return {"oid": self.oid, "name": self.name, "type": self.type, "value": self.value}


@dataclass
class Trap:
    source_ip: str
    source_port: int
    version: str                      # "v1" or "v2c"
    community: str
    pdu: str                          # "trap" or "inform"
    trap_oid: str                     # v2-style notification OID (v1 traps converted per RFC 3584)
    trap_name: str
    uptime: int | None                # TimeTicks (1/100 s) since agent restart
    varbinds: list[VarBind] = field(default_factory=list)
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # v1-only fields
    enterprise: str | None = None
    agent_address: str | None = None
    generic_trap: int | None = None
    specific_trap: int | None = None
    # v3-only fields
    security_name: str | None = None      # USM user name
    security_level: str | None = None     # noAuthNoPriv / authNoPriv / authPriv
    engine_id: str | None = None          # msgAuthoritativeEngineID (hex)
    context_name: str | None = None
    # enrichment
    description: str | None = None        # e.g. Kepware's lastTrapDescr, or the mapping's description
    vendor: str | None = None             # e.g. "Kepware SNMP Agent"
    agent_id: int | None = None           # Kepware agent MIB sub-identifier
    mapped: str | None = None             # "Group.Trap" when a trap mapping matched
    # internal: request-id of an INFORM, needed for the acknowledgement
    request_id: int | None = field(default=None, repr=False)
    tag_updates: list = field(default_factory=list, repr=False, compare=False)   # snmp_driver.Update

    def to_dict(self, include_community: bool = False) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("request_id", "tag_updates", "varbinds")}
        d["varbinds"] = [v.as_dict() for v in self.varbinds]
        if not include_community:
            d.pop("community")
        d["received_at"] = self.received_at.isoformat()
        for k in ("enterprise", "agent_address", "generic_trap", "specific_trap",
                  "security_name", "security_level", "engine_id", "context_name",
                  "description", "vendor", "agent_id", "mapped"):
            if d[k] is None:
                d.pop(k)
        return d

    def to_json(self, **kw) -> str:
        return json.dumps(self.to_dict(**kw), default=str, ensure_ascii=False)

    def varbinds_json(self) -> str:
        return json.dumps([v.as_dict() for v in self.varbinds], default=str, ensure_ascii=False)

    def summary(self) -> str:
        extras = ", ".join(f"{v.name}={v.value}" for v in self.varbinds[:4])
        more = " ..." if len(self.varbinds) > 4 else ""
        who = f" (user {self.security_name})" if self.security_name else ""
        name = self.mapped or self.trap_name
        desc = f" \"{self.description}\"" if self.description else ""
        return f"{self.version} {self.pdu} from {self.source_ip}{who}: {name}{desc} [{extras}{more}]"


def _read_varbinds(data: bytes, start: int, end: int, resolver: OidResolver) -> list[VarBind]:
    out = []
    pos = start
    while pos < end:
        vb_start, vb_end = ber.expect(data, pos, ber.SEQUENCE, end)
        o_start, o_end = ber.expect(data, vb_start, ber.OBJECT_IDENTIFIER, vb_end)
        oid = ber.decode_oid(data[o_start:o_end])
        tag, v_start, v_end = ber.read_tlv(data, o_end, vb_end)
        type_name, value = ber.decode_value(tag, data[v_start:v_end])
        out.append(VarBind(oid, resolver.name(oid), type_name, value, bytes(data[v_start:v_end])))
        pos = vb_end
    return out


@dataclass
class Notification:
    pdu: str
    request_id: int
    trap_oid: str
    uptime: int | None
    varbinds: list[VarBind]
    varbind_list: bytes          # raw encoded varbind list (echoed in INFORM responses)


def parse_notification_pdu(data: bytes, pdu_tag: int, p_start: int, p_end: int,
                           resolver: OidResolver) -> Notification:
    """Parse an SNMPv2-Trap-PDU or InformRequest-PDU body (shared by v2c and v3)."""
    if pdu_tag not in (PDU_TRAP_V2, PDU_INFORM):
        raise UnsupportedMessage(f"PDU type 0x{pdu_tag:02x} is not a notification")
    r_start, r_end = ber.expect(data, p_start, ber.INTEGER, p_end)
    request_id = ber.decode_int(data[r_start:r_end])
    _, _, es_end = ber.read_tlv(data, r_end, p_end)       # error-status (ignored)
    _, _, ei_end = ber.read_tlv(data, es_end, p_end)      # error-index (ignored)
    vl_start, vl_end = ber.expect(data, ei_end, ber.SEQUENCE, p_end)
    uptime = None
    trap_oid = ""
    varbinds = []
    for vb in _read_varbinds(data, vl_start, vl_end, resolver):
        if vb.oid == SYS_UPTIME_0 and uptime is None:
            uptime = vb.value if isinstance(vb.value, int) else None
        elif vb.oid == SNMP_TRAP_OID_0 and not trap_oid and vb.type == "Object Identifier":
            trap_oid = vb.value
        else:
            varbinds.append(vb)
    if not trap_oid:
        raise ber.BerError("notification without snmpTrapOID.0")
    return Notification("inform" if pdu_tag == PDU_INFORM else "trap", request_id, trap_oid, uptime,
                        varbinds, data[ei_end:vl_end])


def parse_message(data: bytes, source: tuple[str, int], resolver: OidResolver) -> Trap:
    """Decode one UDP datagram. Raises ber.BerError or UnsupportedMessage."""
    msg_start, msg_end = ber.expect(data, 0, ber.SEQUENCE)
    v_start, v_end = ber.expect(data, msg_start, ber.INTEGER, msg_end)
    version_num = ber.decode_int(data[v_start:v_end])
    version = VERSIONS.get(version_num, f"unknown({version_num})")
    if version_num not in (0, 1):
        raise UnsupportedMessage(f"SNMP {version} messages are not handled here")

    c_start, c_end = ber.expect(data, v_end, ber.OCTET_STRING, msg_end)
    community = data[c_start:c_end].decode("utf-8", errors="replace")

    pdu_tag, p_start, p_end = ber.read_tlv(data, c_end, msg_end)
    ip, port = source[0], source[1]

    if pdu_tag == PDU_TRAP_V1:
        if version_num != 0:
            raise UnsupportedMessage("v1 Trap-PDU inside a non-v1 message")
        e_start, e_end = ber.expect(data, p_start, ber.OBJECT_IDENTIFIER, p_end)
        enterprise = ber.decode_oid(data[e_start:e_end])
        a_start, a_end = ber.expect(data, e_end, ber.IP_ADDRESS, p_end)
        _, agent_addr = ber.decode_value(ber.IP_ADDRESS, data[a_start:a_end])
        g_start, g_end = ber.expect(data, a_end, ber.INTEGER, p_end)
        generic = ber.decode_int(data[g_start:g_end])
        s_start, s_end = ber.expect(data, g_end, ber.INTEGER, p_end)
        specific = ber.decode_int(data[s_start:s_end])
        t_start, t_end = ber.expect(data, s_end, ber.TIMETICKS, p_end)
        uptime = ber.decode_int(data[t_start:t_end], signed=False)
        vl_start, vl_end = ber.expect(data, t_end, ber.SEQUENCE, p_end)
        varbinds = _read_varbinds(data, vl_start, vl_end, resolver)
        # RFC 3584 section 3.1: map v1 trap identity to a v2 notification OID
        if 0 <= generic <= 5:
            trap_oid = f"{SNMP_TRAPS}.{generic + 1}"
        else:
            trap_oid = f"{enterprise}.0.{specific}"
        return Trap(ip, port, version, community, "trap", trap_oid, resolver.name(trap_oid),
                    uptime, varbinds, enterprise=enterprise, agent_address=agent_addr,
                    generic_trap=generic, specific_trap=specific)

    if pdu_tag in (PDU_TRAP_V2, PDU_INFORM):
        n = parse_notification_pdu(data, pdu_tag, p_start, p_end, resolver)
        return Trap(ip, port, version, community, n.pdu, n.trap_oid, resolver.name(n.trap_oid),
                    n.uptime, n.varbinds, request_id=n.request_id)

    raise UnsupportedMessage(f"PDU type 0x{pdu_tag:02x} is not a notification")


def build_inform_response(data: bytes) -> bytes:
    """Build the Response-PDU that acknowledges an INFORM (RFC 3416 4.2.7).

    The response echoes request-id, community and the original varbind list.
    """
    msg_start, msg_end = ber.expect(data, 0, ber.SEQUENCE)
    _, v_end = ber.expect(data, msg_start, ber.INTEGER, msg_end)
    _, c_end = ber.expect(data, v_end, ber.OCTET_STRING, msg_end)
    pdu_tag, p_start, p_end = ber.read_tlv(data, c_end, msg_end)
    if pdu_tag != PDU_INFORM:
        raise UnsupportedMessage("not an InformRequest")
    _, r_end = ber.expect(data, p_start, ber.INTEGER, p_end)
    _, _, es_end = ber.read_tlv(data, r_end, p_end)
    _, _, ei_end = ber.read_tlv(data, es_end, p_end)
    header = data[msg_start:c_end]                 # version + community, unchanged
    request_id_tlv = data[p_start:r_end]
    varbind_list = data[ei_end:p_end]
    pdu = ber.tlv(PDU_GET_RESPONSE, request_id_tlv + ber.encode_int(0) + ber.encode_int(0) + varbind_list)
    return ber.tlv(ber.SEQUENCE, header + pdu)
