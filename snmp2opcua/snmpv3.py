"""SNMPv3 message processing (RFC 3412) with the User-based Security Model (RFC 3414).

Traps: the sending device is the authoritative engine. Keys are localized to the
device's engine ID taken from the message, so you don't need to configure engine IDs
per device. You can pin them per user if you want to. Replay protection follows
RFC 3414 3.2.7(b).

Informs: the gateway is the authoritative engine. Senders discover our engine ID,
boots and time via a Report PDU (usmStatsUnknownEngineIDs), then send the inform
authenticated and/or encrypted with keys localized to our engine. We answer with an
authenticated/encrypted Response PDU.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

from . import ber
from .oids import OidResolver
from .trap import PDU_GET_RESPONSE, PDU_INFORM, Trap, UnsupportedMessage, parse_notification_pdu
from .usm import UsmError, UsmUser

log = logging.getLogger("snmp2opcua.snmpv3")

PDU_REPORT = 0xA8
FLAG_AUTH, FLAG_PRIV, FLAG_REPORTABLE = 0x01, 0x02, 0x04
USM_SECURITY_MODEL = 3
TIME_WINDOW = 150
MAX_BOOTS = 2147483647
MAX_MSG_SIZE = 65507
UNKNOWN_REQUEST_ID = 0x7FFFFFFF

USM_STATS = {
    "unsupportedSecLevels": "1.3.6.1.6.3.15.1.1.1.0",
    "notInTimeWindows": "1.3.6.1.6.3.15.1.1.2.0",
    "unknownUserNames": "1.3.6.1.6.3.15.1.1.3.0",
    "unknownEngineIDs": "1.3.6.1.6.3.15.1.1.4.0",
    "wrongDigests": "1.3.6.1.6.3.15.1.1.5.0",
    "decryptionErrors": "1.3.6.1.6.3.15.1.1.6.0",
}
STAT_BY_OID = {v: k for k, v in USM_STATS.items()}


class V3Rejected(Exception):
    """Message refused by USM. ``reply`` is an optional Report PDU to send back."""

    def __init__(self, reason: str, reply: bytes | None = None):
        super().__init__(reason)
        self.reply = reply


# --------------------------------------------------------------------------
# Wire format
# --------------------------------------------------------------------------
@dataclass
class V3Header:
    msg_id: int
    max_size: int
    flags: int
    security_model: int
    engine_id: bytes
    boots: int
    engine_time: int
    user: bytes
    auth_params: bytes
    auth_offset: int          # absolute offset of msgAuthenticationParameters content
    priv_params: bytes
    data_tag: int             # SEQUENCE (plaintext ScopedPDU) or OCTET STRING (encrypted)
    data_pos: int             # where the msgData TLV begins
    data_start: int
    data_end: int

    @property
    def level(self) -> str:
        if self.flags & FLAG_PRIV:
            return "authPriv"
        return "authNoPriv" if self.flags & FLAG_AUTH else "noAuthNoPriv"


def peek_version(data: bytes) -> int:
    msg_start, msg_end = ber.expect(data, 0, ber.SEQUENCE)
    v_start, v_end = ber.expect(data, msg_start, ber.INTEGER, msg_end)
    return ber.decode_int(data[v_start:v_end])


def parse_header(data: bytes) -> V3Header:
    msg_start, msg_end = ber.expect(data, 0, ber.SEQUENCE)
    v_start, v_end = ber.expect(data, msg_start, ber.INTEGER, msg_end)
    if ber.decode_int(data[v_start:v_end]) != 3:
        raise UnsupportedMessage("not an SNMPv3 message")
    g_start, g_end = ber.expect(data, v_end, ber.SEQUENCE, msg_end)
    a, b = ber.expect(data, g_start, ber.INTEGER, g_end)
    msg_id = ber.decode_int(data[a:b])
    a, b = ber.expect(data, b, ber.INTEGER, g_end)
    max_size = ber.decode_int(data[a:b])
    a, b = ber.expect(data, b, ber.OCTET_STRING, g_end)
    if b - a < 1:
        raise ber.BerError("empty msgFlags")
    flags = data[a]
    a, b = ber.expect(data, b, ber.INTEGER, g_end)
    model = ber.decode_int(data[a:b])

    s_start, s_end = ber.expect(data, g_end, ber.OCTET_STRING, msg_end)
    u_start, u_end = ber.expect(data, s_start, ber.SEQUENCE, s_end)
    a, b = ber.expect(data, u_start, ber.OCTET_STRING, u_end)
    engine_id = data[a:b]
    a, b = ber.expect(data, b, ber.INTEGER, u_end)
    boots = ber.decode_int(data[a:b])
    a, b = ber.expect(data, b, ber.INTEGER, u_end)
    engine_time = ber.decode_int(data[a:b])
    a, b = ber.expect(data, b, ber.OCTET_STRING, u_end)
    user = data[a:b]
    auth_start, auth_end = ber.expect(data, b, ber.OCTET_STRING, u_end)
    a, b = ber.expect(data, auth_end, ber.OCTET_STRING, u_end)
    priv_params = data[a:b]

    tag, d_start, d_end = ber.read_tlv(data, s_end, msg_end)
    if tag not in (ber.SEQUENCE, ber.OCTET_STRING):
        raise ber.BerError("bad msgData")
    if len(engine_id) > 32 or len(user) > 32:
        raise ber.BerError("engine ID / user name too long")
    if not 0 <= boots <= MAX_BOOTS or not 0 <= engine_time <= MAX_BOOTS:
        raise ber.BerError("engine boots/time out of range")
    return V3Header(msg_id, max_size, flags, model, engine_id, boots, engine_time, user,
                    data[auth_start:auth_end], auth_start, priv_params, tag, s_end, d_start, d_end)


def parse_scoped_pdu(buf: bytes):
    """Returns (context_engine_id, context_name, pdu_tag, pdu_start, pdu_end). Trailing padding is ignored."""
    s_start, s_end = ber.expect(buf, 0, ber.SEQUENCE)
    a, b = ber.expect(buf, s_start, ber.OCTET_STRING, s_end)
    ctx_engine = buf[a:b]
    a, b = ber.expect(buf, b, ber.OCTET_STRING, s_end)
    ctx_name = buf[a:b]
    tag, p_start, p_end = ber.read_tlv(buf, b, s_end)
    return ctx_engine, ctx_name, tag, p_start, p_end


def build_scoped_pdu(context_engine_id: bytes, context_name: bytes, pdu_tag: int, pdu_body: bytes) -> bytes:
    return ber.sequence(ber.encode_octets(context_engine_id), ber.encode_octets(context_name),
                        ber.tlv(pdu_tag, pdu_body))


def build_message(*, msg_id: int, engine_id: bytes, boots: int, engine_time: int, user_name: bytes,
                  scoped_pdu: bytes, user: UsmUser | None = None, level: str = "noAuthNoPriv",
                  reportable: bool = False) -> bytes:
    """Build (and if needed encrypt + sign) a complete SNMPv3 message."""
    auth = level in ("authNoPriv", "authPriv")
    priv = level == "authPriv"
    if (auth and (user is None or user.auth is None)) or (priv and user.priv is None):
        raise UsmError(f"user cannot send at security level {level}")
    flags = (FLAG_AUTH if auth else 0) | (FLAG_PRIV if priv else 0) | (FLAG_REPORTABLE if reportable else 0)
    priv_params = b""
    msg_data = scoped_pdu
    if priv:
        ciphertext, priv_params = user.priv.encrypt(user.priv_key(engine_id), boots, engine_time, scoped_pdu)
        msg_data = ber.encode_octets(ciphertext)

    def assemble(auth_params: bytes) -> bytes:
        usm = ber.sequence(ber.encode_octets(engine_id), ber.encode_int(boots), ber.encode_int(engine_time),
                           ber.encode_octets(user_name), ber.encode_octets(auth_params),
                           ber.encode_octets(priv_params))
        header = ber.sequence(ber.encode_int(msg_id), ber.encode_int(MAX_MSG_SIZE),
                              ber.encode_octets(bytes([flags])), ber.encode_int(USM_SECURITY_MODEL))
        return ber.sequence(ber.encode_int(3), header, ber.encode_octets(usm), msg_data)

    if not auth:
        return assemble(b"")
    placeholder = assemble(b"\x00" * user.auth.mac_len)
    return assemble(user.auth.mac(user.auth_key(engine_id), placeholder))


def verify_auth(data: bytes, h: V3Header, user: UsmUser) -> bool:
    if len(h.auth_params) != user.auth.mac_len:
        return False
    zeroed = data[:h.auth_offset] + b"\x00" * len(h.auth_params) + data[h.auth_offset + len(h.auth_params):]
    return user.auth.verify(user.auth_key(h.engine_id), zeroed, h.auth_params)


def scoped_plaintext(data: bytes, h: V3Header, user: UsmUser | None) -> bytes:
    """Return the ScopedPDU bytes, decrypting if the message is encrypted."""
    if h.flags & FLAG_PRIV:
        if h.data_tag != ber.OCTET_STRING:
            raise UsmError("encrypted message without encryptedPDU")
        return user.priv.decrypt(user.priv_key(h.engine_id), h.boots, h.engine_time, h.priv_params,
                                 data[h.data_start:h.data_end])
    if h.data_tag != ber.SEQUENCE:
        raise ber.BerError("plaintext message without ScopedPDU")
    return data[h.data_pos:h.data_end]


# --------------------------------------------------------------------------
# Local engine identity (engine ID + boots persisted across restarts)
# --------------------------------------------------------------------------
def load_engine_state(state_file: str | None, configured_engine_id: str | None) -> tuple[bytes, int]:
    """Return (engine_id, boots). Boots is incremented on every start, as RFC 3414 requires."""
    wanted = bytes.fromhex(configured_engine_id.replace(":", "").replace(" ", "")) if configured_engine_id else None
    if wanted is not None and not 5 <= len(wanted) <= 32:
        raise ValueError("snmp.v3.engine_id must be 5..32 octets (hex)")
    state = {}
    path = Path(state_file) if state_file else None
    if path and path.exists():
        try:
            state = json.loads(path.read_text())
        except (OSError, ValueError):
            log.warning("Could not read %s; starting a new engine state", path)
    stored = bytes.fromhex(state["engine_id"]) if state.get("engine_id") else None
    engine_id = wanted or stored or (b"\x80\x00\x1f\x88\x05" + os.urandom(8))  # RFC 3411 format, random octets
    boots = int(state.get("boots", 0)) + 1 if stored == engine_id else 1
    boots = min(boots, MAX_BOOTS)
    if path:
        try:
            path.write_text(json.dumps({"engine_id": engine_id.hex(), "boots": boots}))
        except OSError as exc:
            log.warning("Could not write SNMPv3 engine state to %s (%s). Informs still work, but "
                        "engine boots won't persist across restarts.", path, exc)
    return engine_id, boots


# --------------------------------------------------------------------------
# The engine
# --------------------------------------------------------------------------
class SnmpV3Engine:
    def __init__(self, engine_id: bytes, boots: int, users: list[UsmUser], resolver: OidResolver,
                 replay_protection: bool = True):
        self.engine_id = engine_id
        self.boots = boots
        self.users = {u.name.encode("utf-8"): u for u in users}
        self.resolver = resolver
        self.replay_protection = replay_protection
        self._start = time.monotonic()
        self._remote: dict[bytes, tuple[int, int, float]] = {}   # engineID -> (boots, latest time, seen at)
        self.counters = {k: 0 for k in USM_STATS}

    def engine_time(self) -> int:
        return int(time.monotonic() - self._start) & MAX_BOOTS

    def remote_engines(self) -> list[dict]:
        """Devices whose traps authenticated, for diagnostics (newest first)."""
        now = time.monotonic()
        rows = [{"engine_id": eid.hex(), "boots": b, "engine_time": t, "seen_ago": int(now - seen)}
                for eid, (b, t, seen) in list(self._remote.items())]
        return sorted(rows, key=lambda r: r["seen_ago"])

    # ------------------------------------------------------------------ replies
    def _report(self, h: V3Header, stat: str, request_id: int, user: UsmUser | None = None) -> bytes:
        self.counters[stat] += 1
        vb = ber.sequence(ber.encode_oid(USM_STATS[stat]), ber.encode_int(self.counters[stat], ber.COUNTER32))
        body = ber.encode_int(request_id) + ber.encode_int(0) + ber.encode_int(0) + ber.sequence(vb)
        scoped = build_scoped_pdu(self.engine_id, b"", PDU_REPORT, body)
        level = "authNoPriv" if user is not None else "noAuthNoPriv"
        return build_message(msg_id=h.msg_id, engine_id=self.engine_id, boots=self.boots,
                             engine_time=self.engine_time(), user_name=h.user, scoped_pdu=scoped,
                             user=user, level=level)

    def _reject_stale(self, h: V3Header):
        self.counters["notInTimeWindows"] += 1
        raise V3Rejected(
            f"replayed or stale trap from engine {h.engine_id.hex()} (boots={h.boots}, time={h.engine_time}). "
            "If this device resets engineBoots on reboot, set snmp.v3.replay_protection: false")

    def _refuse(self, stat: str, reason: str, data: bytes, h: V3Header, user: UsmUser | None = None):
        """Count a USM failure and raise V3Rejected, with a Report if the sender asked for one."""
        if h.flags & FLAG_REPORTABLE:
            raise V3Rejected(reason, self._report(h, stat, self._plain_request_id(data, h), user))
        self.counters[stat] += 1
        raise V3Rejected(reason)

    def _plain_request_id(self, data: bytes, h: V3Header) -> int:
        if h.flags & FLAG_PRIV:
            return UNKNOWN_REQUEST_ID
        try:
            buf = scoped_plaintext(data, h, None)
            _, _, _, p_start, p_end = parse_scoped_pdu(buf)
            a, b = ber.expect(buf, p_start, ber.INTEGER, p_end)
            return ber.decode_int(buf[a:b])
        except (ber.BerError, UsmError):
            return UNKNOWN_REQUEST_ID

    def _remote_time_ok(self, engine_id: bytes, boots: int, engine_time: int) -> bool:
        """RFC 3414 3.2.7(b): non-authoritative timeliness / replay check for traps."""
        now = time.monotonic()
        cached = self._remote.get(engine_id)
        if cached is not None:
            c_boots, c_time, seen = cached
            estimated = c_time + int(now - seen)
            if c_boots == MAX_BOOTS or boots < c_boots or (boots == c_boots and engine_time < estimated - TIME_WINDOW):
                return False
            if not (boots > c_boots or engine_time > c_time):
                return True
        if len(self._remote) > 10000:
            self._remote.clear()
        self._remote[engine_id] = (boots, engine_time, now)
        return True

    # ------------------------------------------------------------------ main entry
    def handle(self, data: bytes, source: tuple) -> tuple[Trap | None, bytes | None]:
        """Process one SNMPv3 datagram.

        Returns (trap, reply). trap is None for discovery probes; reply is a Report or
        Response to send back (or None). Raises V3Rejected, UsmError, ber.BerError or
        UnsupportedMessage for messages that must be dropped.
        """
        h = parse_header(data)
        if h.security_model != USM_SECURITY_MODEL:
            raise UnsupportedMessage(f"security model {h.security_model} (only USM=3 is supported)")
        if h.flags & FLAG_PRIV and not h.flags & FLAG_AUTH:
            raise ber.BerError("invalid msgFlags: privacy without authentication")
        reportable = bool(h.flags & FLAG_REPORTABLE)
        authoritative = h.engine_id == self.engine_id
        user_label = h.user.decode("utf-8", "replace")

        # Confirmed-class message (INFORM / discovery probe) not addressed to our engine:
        # tell the sender our engine ID, boots and time.
        if reportable and not authoritative:
            if not h.engine_id:
                log.debug("SNMPv3 engine discovery from %s", source[0])
            return None, self._report(h, "unknownEngineIDs", self._plain_request_id(data, h))

        user = self.users.get(h.user)
        if user is None:
            self._refuse("unknownUserNames", f"unknown SNMPv3 user {user_label!r}", data, h)
        level_ok = h.level == user.level
        # An authNoPriv time-sync probe for an authPriv user still deserves a notInTimeWindows Report,
        # so let it through to the timeliness check; it is refused right after that.
        sync_probe = authoritative and h.level == "authNoPriv" and user.level == "authPriv"
        if not level_ok and not sync_probe:
            self._refuse("unsupportedSecLevels",
                         f"user {user_label!r} sent {h.level}, but is configured for {user.level}", data, h)

        if not authoritative:
            if not h.engine_id:
                raise V3Rejected("SNMPv3 trap with empty engine ID")
            if user.engine_ids and h.engine_id not in user.engine_ids:
                raise V3Rejected(f"engine ID {h.engine_id.hex()} not allowed for user {user_label!r}")

        if user.auth is not None:
            if not verify_auth(data, h, user):
                self._refuse("wrongDigests",
                             f"authentication failed for user {user_label!r} (wrong auth key or protocol)", data, h)
            if authoritative:
                now = self.engine_time()
                if h.boots != self.boots or self.boots == MAX_BOOTS or abs(h.engine_time - now) > TIME_WINDOW:
                    # authenticated Report so the sender can trust our boots/time and resynchronize
                    self._refuse("notInTimeWindows", f"message from user {user_label!r} outside the time window",
                                 data, h, user)
            elif not self._remote_time_ok(h.engine_id, h.boots, h.engine_time):
                if not self.replay_protection:      # accepted anyway; remember the latest values
                    self._remote[h.engine_id] = (h.boots, h.engine_time, time.monotonic())
                else:
                    self._reject_stale(h)
        if not level_ok:
            self._refuse("unsupportedSecLevels",
                         f"user {user_label!r} sent {h.level}, but is configured for {user.level}", data, h)

        try:
            buf = scoped_plaintext(data, h, user)
            ctx_engine, ctx_name, pdu_tag, p_start, p_end = parse_scoped_pdu(buf)
        except (UsmError, ber.BerError) as exc:
            if h.flags & FLAG_PRIV:
                self.counters["decryptionErrors"] += 1
                raise V3Rejected(f"decryption failed for user {user_label!r} (wrong priv key or protocol)") from exc
            raise

        note = parse_notification_pdu(buf, pdu_tag, p_start, p_end, self.resolver)
        if note.pdu == "inform" and not authoritative:
            raise V3Rejected("INFORM not addressed to this engine")

        trap = Trap(source[0], source[1], "v3", "", note.pdu, note.trap_oid, self.resolver.name(note.trap_oid),
                    note.uptime, note.varbinds, security_name=user.name, security_level=h.level,
                    engine_id=h.engine_id.hex(), context_name=ctx_name.decode("utf-8", "replace"),
                    request_id=note.request_id)

        reply = None
        if pdu_tag == PDU_INFORM:
            body = ber.encode_int(note.request_id) + ber.encode_int(0) + ber.encode_int(0) + note.varbind_list
            scoped = build_scoped_pdu(ctx_engine, ctx_name, PDU_GET_RESPONSE, body)
            reply = build_message(msg_id=h.msg_id, engine_id=self.engine_id, boots=self.boots,
                                  engine_time=self.engine_time(), user_name=h.user, scoped_pdu=scoped,
                                  user=user, level=h.level)
        return trap, reply
