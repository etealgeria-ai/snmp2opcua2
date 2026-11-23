"""Send a test SNMP trap or inform (v1, v2c or v3). No net-snmp needed.

Examples:
  python -m snmp2opcua.sendtrap --port 1162 --trap-oid linkDown \\
      -v ifIndex.3 i 3 -v ifDescr.3 s eth3
  python -m snmp2opcua.sendtrap --port 1162 --inform --trap-oid 1.3.6.1.4.1.9999.0.1 -v 1.3.6.1.4.1.9999.1 s "Door open"
  python -m snmp2opcua.sendtrap --port 1162 --snmp-version 1 --enterprise 1.3.6.1.4.1.9999 --generic 6 --specific 7

  # SNMPv3 trap (authPriv) and inform (with engine discovery)
  python -m snmp2opcua.sendtrap --port 1162 --snmp-version 3 -u opcgw -a SHA256 -A authpass123 \\
      -x AES -X privpass123 --trap-oid linkDown -v ifIndex.3 i 3
  python -m snmp2opcua.sendtrap --port 1162 --snmp-version 3 -u opcgw -a SHA256 -A authpass123 \\
      -x AES -X privpass123 --inform --trap-oid coldStart

Varbind types (net-snmp letters): i INTEGER, u Gauge32, c Counter32, C Counter64, t TimeTicks,
a IpAddress, o OID, s STRING, x hex STRING, n NULL
"""
from __future__ import annotations

import argparse
import random
import socket
import sys
import time

from . import ber
from .oids import BUILTIN_NAMES, SNMP_TRAP_OID_0, SYS_UPTIME_0
from .snmpv3 import FLAG_AUTH, PDU_REPORT, STAT_BY_OID, build_message, build_scoped_pdu, parse_header, \
    parse_scoped_pdu, scoped_plaintext, verify_auth
from .trap import PDU_GET_RESPONSE, PDU_INFORM, PDU_TRAP_V1, PDU_TRAP_V2
from .usm import UsmUser

NAME_TO_OID = {v: k for k, v in BUILTIN_NAMES.items()}
PDU_GET = 0xA0
DEFAULT_V3_ENGINE_ID = "80001f880473656e6474726170"   # RFC 3411 text format: "sendtrap"


def to_oid(text: str) -> str:
    """Accept numeric OIDs or known names, optionally with an index: ``ifDescr.3``."""
    head, _, tail = text.strip(".").partition(".")
    if head in NAME_TO_OID:
        return NAME_TO_OID[head] + ("." + tail if tail else "")
    return text


def encode_typed(kind: str, value: str) -> bytes:
    if kind == "i":
        return ber.encode_int(int(value))
    if kind == "u":
        return ber.encode_int(int(value), ber.GAUGE32)
    if kind == "c":
        return ber.encode_int(int(value), ber.COUNTER32)
    if kind == "C":
        return ber.encode_int(int(value), ber.COUNTER64)
    if kind == "t":
        return ber.encode_int(int(value), ber.TIMETICKS)
    if kind == "a":
        return ber.encode_ip(value)
    if kind == "o":
        return ber.encode_oid(to_oid(value))
    if kind == "s":
        return ber.encode_octets(value)
    if kind == "x":
        return ber.encode_octets(bytes.fromhex(value.replace(":", "").replace(" ", "")))
    if kind == "n":
        return ber.encode_null()
    raise ValueError(f"unknown varbind type {kind!r}")


def varbind(oid: str, value_tlv: bytes) -> bytes:
    return ber.sequence(ber.encode_oid(to_oid(oid)), value_tlv)


def notification_body(trap_oid: str, uptime: int, varbinds: list[bytes], request_id: int) -> bytes:
    vbs = [varbind(SYS_UPTIME_0, ber.encode_int(uptime, ber.TIMETICKS)),
           varbind(SNMP_TRAP_OID_0, ber.encode_oid(to_oid(trap_oid)))] + varbinds
    return ber.encode_int(request_id) + ber.encode_int(0) + ber.encode_int(0) + ber.sequence(*vbs)


def build_v2(community: str, trap_oid: str, uptime: int, varbinds: list[bytes],
             inform: bool = False, request_id: int | None = None) -> bytes:
    request_id = random.randint(1, 2**31 - 1) if request_id is None else request_id
    pdu = ber.tlv(PDU_INFORM if inform else PDU_TRAP_V2, notification_body(trap_oid, uptime, varbinds, request_id))
    return ber.sequence(ber.encode_int(1), ber.encode_octets(community), pdu)


def build_v1(community: str, enterprise: str, agent_addr: str, generic: int, specific: int,
             uptime: int, varbinds: list[bytes]) -> bytes:
    pdu = ber.tlv(PDU_TRAP_V1, ber.encode_oid(enterprise) + ber.encode_ip(agent_addr)
                  + ber.encode_int(generic) + ber.encode_int(specific)
                  + ber.encode_int(uptime, ber.TIMETICKS) + ber.sequence(*varbinds))
    return ber.sequence(ber.encode_int(0), ber.encode_octets(community), pdu)


def build_v3(user: UsmUser, engine_id: bytes, boots: int, engine_time: int, trap_oid: str, uptime: int,
             varbinds: list[bytes], inform: bool = False, request_id: int | None = None,
             msg_id: int | None = None, context_name: bytes = b"") -> bytes:
    request_id = random.randint(1, 2**31 - 1) if request_id is None else request_id
    msg_id = random.randint(1, 2**31 - 1) if msg_id is None else msg_id
    scoped = build_scoped_pdu(engine_id, context_name, PDU_INFORM if inform else PDU_TRAP_V2,
                              notification_body(trap_oid, uptime, varbinds, request_id))
    return build_message(msg_id=msg_id, engine_id=engine_id, boots=boots, engine_time=engine_time,
                         user_name=user.name.encode(), scoped_pdu=scoped, user=user, level=user.level,
                         reportable=inform)


def discovery_probe(msg_id: int | None = None) -> bytes:
    """Unauthenticated, reportable GET with empty engine ID (RFC 3414 4)."""
    msg_id = random.randint(1, 2**31 - 1) if msg_id is None else msg_id
    body = ber.encode_int(random.randint(1, 2**31 - 1)) + ber.encode_int(0) + ber.encode_int(0) + ber.sequence()
    return build_message(msg_id=msg_id, engine_id=b"", boots=0, engine_time=0, user_name=b"",
                         scoped_pdu=build_scoped_pdu(b"", b"", PDU_GET, body), reportable=True)


def read_v3_reply(data: bytes, user: UsmUser):
    """Parse a v3 Report/Response. Returns (header, pdu_tag, request_id, report_stat_or_None)."""
    h = parse_header(data)
    if h.flags & FLAG_AUTH and not verify_auth(data, h, user):
        raise ValueError("reply failed authentication")
    buf = scoped_plaintext(data, h, user)
    _, _, tag, p_start, p_end = parse_scoped_pdu(buf)
    a, b = ber.expect(buf, p_start, ber.INTEGER, p_end)
    request_id = ber.decode_int(buf[a:b])
    stat = None
    if tag == PDU_REPORT:
        oids = [buf[s:e] for s, e in _report_oids(buf, b, p_end)]
        stat = next((STAT_BY_OID.get(ber.decode_oid(o)) for o in oids), None) or "unknown report"
    return h, tag, request_id, stat


def _report_oids(buf, pos, end):
    _, _, es_end = ber.read_tlv(buf, pos, end)
    _, _, ei_end = ber.read_tlv(buf, es_end, end)
    vl_start, vl_end = ber.expect(buf, ei_end, ber.SEQUENCE, end)
    p = vl_start
    while p < vl_end:
        vb_start, vb_end = ber.expect(buf, p, ber.SEQUENCE, vl_end)
        yield ber.expect(buf, vb_start, ber.OBJECT_IDENTIFIER, vb_end)
        p = vb_end


def send_v3_inform(sock, addr, user: UsmUser, trap_oid: str, uptime: int, varbinds: list[bytes],
                   context_name: bytes = b"", timeout: float = 3.0) -> str:
    """Discover the receiver's engine, send the inform, verify the acknowledgement."""
    sock.settimeout(timeout)
    sock.sendto(discovery_probe(), addr)
    h, _, _, stat = read_v3_reply(sock.recvfrom(65535)[0], user)
    engine_id, boots, base_time, base_clock = h.engine_id, h.boots, h.engine_time, time.monotonic()
    print(f"Discovered engine {engine_id.hex()} (boots {boots}, time {base_time})")
    for _ in range(2):
        request_id = random.randint(1, 2**31 - 1)
        etime = base_time + int(time.monotonic() - base_clock)
        sock.sendto(build_v3(user, engine_id, boots, etime, trap_oid, uptime, varbinds, inform=True,
                             request_id=request_id, context_name=context_name), addr)
        h, tag, rid, stat = read_v3_reply(sock.recvfrom(65535)[0], user)
        if tag == PDU_GET_RESPONSE and rid == request_id:
            return f"Inform acknowledged ({h.level} response)"
        if stat == "notInTimeWindows":     # resynchronize from the authenticated report and retry
            boots, base_time, base_clock = h.boots, h.engine_time, time.monotonic()
            continue
        raise ValueError(f"inform refused by receiver: {stat or hex(tag)}")
    raise ValueError("could not synchronize engine time with the receiver")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Send a test SNMP trap/inform",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=162)
    ap.add_argument("--snmp-version", choices=["1", "2c", "3"], default="2c")
    ap.add_argument("--community", default="public", help="v1/v2c community")
    ap.add_argument("--trap-oid", default="linkDown", help="notification OID or known name")
    ap.add_argument("--inform", action="store_true", help="send an INFORM and wait for the ack (v2c/v3)")
    ap.add_argument("--uptime", type=int, default=None, help="TimeTicks (default: derived from clock)")
    ap.add_argument("-v", "--varbind", nargs=3, action="append", default=[], metavar=("OID", "TYPE", "VALUE"))
    v1 = ap.add_argument_group("SNMPv1")
    v1.add_argument("--enterprise", default="1.3.6.1.4.1.8072.3.2.10", help="enterprise OID")
    v1.add_argument("--agent-addr", default="127.0.0.1", help="agent address")
    v1.add_argument("--generic", type=int, default=6, help="generic-trap (0-6)")
    v1.add_argument("--specific", type=int, default=1, help="specific-trap")
    v3 = ap.add_argument_group("SNMPv3")
    v3.add_argument("-u", "--user", help="USM user name")
    v3.add_argument("-a", "--auth-protocol", default="NONE", help="MD5, SHA, SHA224, SHA256, SHA384, SHA512")
    v3.add_argument("-A", "--auth-key", help="authentication passphrase")
    v3.add_argument("-x", "--priv-protocol", default="NONE", help="DES, AES, AES192, AES256, AES192C, AES256C")
    v3.add_argument("-X", "--priv-key", help="privacy passphrase")
    v3.add_argument("-e", "--engine-id", default=DEFAULT_V3_ENGINE_ID, help="sender engine ID (hex) for traps")
    v3.add_argument("--boots", type=int, default=1, help="sender engine boots for traps")
    v3.add_argument("-n", "--context", default="", help="context name")
    args = ap.parse_args(argv)

    uptime = args.uptime if args.uptime is not None else int(time.monotonic() * 100) & 0xFFFFFFFF
    vbs = [varbind(oid, encode_typed(kind, value)) for oid, kind, value in args.varbind]
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    addr = (args.host, args.port)

    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        if args.snmp_version == "3":
            if not args.user:
                ap.error("SNMPv3 needs --user")
            try:
                user = UsmUser.create(args.user, args.auth_protocol, args.auth_key, args.priv_protocol, args.priv_key)
            except ValueError as exc:
                ap.error(str(exc))
            if args.inform:
                try:
                    print(send_v3_inform(sock, addr, user, args.trap_oid, uptime, vbs, args.context.encode()))
                    return 0
                except (socket.timeout, ValueError) as exc:
                    print(f"Inform failed: {exc or 'no reply within timeout'}", file=sys.stderr)
                    return 1
            packet = build_v3(user, bytes.fromhex(args.engine_id), args.boots, int(time.time()) & 0x7FFFFFFF,
                              args.trap_oid, uptime, vbs, context_name=args.context.encode())
            sock.sendto(packet, addr)
            print(f"Sent {len(packet)}-byte SNMPv3 trap ({user.level}, user {user.name}) to {args.host}:{args.port}")
            return 0

        if args.snmp_version == "1":
            if args.inform:
                ap.error("INFORM requires SNMP v2c or v3")
            packet = build_v1(args.community, args.enterprise, args.agent_addr, args.generic,
                              args.specific, uptime, vbs)
        else:
            packet = build_v2(args.community, args.trap_oid, uptime, vbs, inform=args.inform)
        sock.sendto(packet, addr)
        print(f"Sent {len(packet)}-byte SNMPv{args.snmp_version} {'inform' if args.inform else 'trap'} "
              f"to {args.host}:{args.port}")
        if args.inform:
            sock.settimeout(3)
            try:
                reply, _ = sock.recvfrom(65535)
                print(f"Inform acknowledged ({len(reply)} bytes)")
            except socket.timeout:
                print("No acknowledgement within 3 s", file=sys.stderr)
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
