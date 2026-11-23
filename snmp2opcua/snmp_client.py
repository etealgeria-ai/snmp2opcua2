"""Minimal asyncio SNMP v1/v2c manager for polling (GET, GETNEXT, GETBULK, walk).

Built on the gateway's own BER code, so no pysnmp is needed. ``walk()`` behaves like
pysnmp's ``nextCmd(..., lexicographicMode=False)``: it returns the rows under the
given column OID and stops at the first OID outside it.
"""
from __future__ import annotations

import asyncio
import random

from . import ber
from .oids import OidResolver
from .trap import VarBind

PDU_GET, PDU_GETNEXT, PDU_RESPONSE, PDU_GETBULK = 0xA0, 0xA1, 0xA2, 0xA5

# RFC 3416 error-status values (names as in SNMP agent manuals)
ERROR_STATUS = {
    0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess",
    7: "wrongType", 8: "wrongLength", 9: "wrongEncoding", 10: "wrongValue", 11: "noCreation",
    12: "inconsistentValue", 13: "resourceUnavailable", 14: "commitFailed", 15: "undoFailed",
    16: "authorizationError", 17: "notWritable", 18: "inconsistentName",
}
END_TYPES = {"EndOfMibView"}
MISSING_TYPES = {"NoSuchObject", "NoSuchInstance"}


class SnmpTimeout(Exception):
    """No response after all retries."""


class SnmpErrorStatus(Exception):
    def __init__(self, status: int, index: int, oid: str | None = None):
        self.status, self.index, self.oid = status, index, oid
        name = ERROR_STATUS.get(status, f"error {status}")
        where = f" (OID {oid})" if oid else (f" (variable {index})" if index else "")
        super().__init__(f"{name}{where}")

    @property
    def name(self) -> str:
        return ERROR_STATUS.get(self.status, str(self.status))


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.waiters: dict[int, asyncio.Future] = {}

    def datagram_received(self, data, addr):
        try:
            req_id, payload = parse_response(data)
        except (ber.BerError, ValueError):
            return
        fut = self.waiters.pop(req_id, None)
        if fut is not None and not fut.done():
            fut.set_result(payload)

    def error_received(self, exc):
        for fut in self.waiters.values():
            if not fut.done():
                fut.set_exception(exc)
        self.waiters.clear()


def parse_response(data: bytes):
    """Returns (request_id, (version, community, error_status, error_index, varbind TLVs))."""
    ms, me = ber.expect(data, 0, ber.SEQUENCE)
    vs, ve = ber.expect(data, ms, ber.INTEGER, me)
    version = ber.decode_int(data[vs:ve])
    cs, ce = ber.expect(data, ve, ber.OCTET_STRING, me)
    community = data[cs:ce]
    tag, ps, pe = ber.read_tlv(data, ce, me)
    if tag != PDU_RESPONSE:
        raise ValueError("not a Response-PDU")
    rs, re_ = ber.expect(data, ps, ber.INTEGER, pe)
    es, ee = ber.expect(data, re_, ber.INTEGER, pe)
    xs, xe = ber.expect(data, ee, ber.INTEGER, pe)
    ls, le = ber.expect(data, xe, ber.SEQUENCE, pe)
    raw = []
    pos = ls
    while pos < le:
        vbs, vbe = ber.expect(data, pos, ber.SEQUENCE, le)
        os_, oe = ber.expect(data, vbs, ber.OBJECT_IDENTIFIER, vbe)
        vtag, vs_, ve_ = ber.read_tlv(data, oe, vbe)
        raw.append((ber.decode_oid(data[os_:oe]), vtag, bytes(data[vs_:ve_])))
        pos = vbe
    return ber.decode_int(data[rs:re_]), (version, community, ber.decode_int(data[es:ee]),
                                           ber.decode_int(data[xs:xe]), raw)


class SnmpClient:
    """One agent. Reuses a single UDP socket; safe for sequential use from one asyncio task."""

    def __init__(self, host: str, community: str = "public", version: str = "2c", port: int = 161,
                 timeout: float = 2.0, retries: int = 1, resolver: OidResolver | None = None):
        if version not in ("1", "2c"):
            raise ValueError("polling supports SNMP version 1 or 2c")
        self.host, self.port, self.community = host, port, community.encode()
        self.version = version
        self.timeout, self.retries = timeout, retries
        self.resolver = resolver or OidResolver()
        self._transport: asyncio.DatagramTransport | None = None
        self._proto: _Protocol | None = None
        self.requests = 0
        self.timeouts = 0

    async def _ensure(self) -> None:
        if self._transport is None or self._transport.is_closing():
            loop = asyncio.get_running_loop()
            self._transport, proto = await loop.create_datagram_endpoint(_Protocol,
                                                                         remote_addr=(self.host, self.port))
            self._proto = proto  # type: ignore[assignment]

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def _message(self, pdu_tag: int, req_id: int, oids: list[str], a: int = 0, b: int = 0) -> bytes:
        vbs = [ber.sequence(ber.encode_oid(o), ber.encode_null()) for o in oids]
        pdu = ber.tlv(pdu_tag, ber.encode_int(req_id) + ber.encode_int(a) + ber.encode_int(b) + ber.sequence(*vbs))
        return ber.sequence(ber.encode_int(0 if self.version == "1" else 1), ber.encode_octets(self.community), pdu)

    async def _request(self, pdu_tag: int, oids: list[str], a: int = 0, b: int = 0) -> list[VarBind]:
        await self._ensure()
        assert self._transport is not None and self._proto is not None
        loop = asyncio.get_running_loop()
        for _attempt in range(self.retries + 1):
            req_id = random.randint(1, 2**31 - 1)
            fut: asyncio.Future = loop.create_future()
            self._proto.waiters[req_id] = fut
            self.requests += 1
            self._transport.sendto(self._message(pdu_tag, req_id, oids, a, b))
            try:
                _version, community, status, index, raw = await asyncio.wait_for(fut, self.timeout)
            except asyncio.TimeoutError:
                self._proto.waiters.pop(req_id, None)
                self.timeouts += 1
                continue
            if community != self.community:
                continue        # not for us; treat like no answer
            if status:
                oid = oids[index - 1] if 0 < index <= len(oids) and pdu_tag != PDU_GETBULK else None
                raise SnmpErrorStatus(status, index, oid)
            out = []
            for oid, vtag, content in raw:
                type_name, value = ber.decode_value(vtag, content)
                out.append(VarBind(oid, self.resolver.name(oid), type_name, value, content))
            return out
        raise SnmpTimeout(f"no response from {self.host}:{self.port} after {self.retries + 1} attempt(s) "
                          f"of {self.timeout:g} s")

    async def get(self, oids: list[str]) -> list[VarBind]:
        return await self._request(PDU_GET, oids)

    async def getnext(self, oids: list[str]) -> list[VarBind]:
        return await self._request(PDU_GETNEXT, oids)

    async def getbulk(self, oids: list[str], max_repetitions: int = 10, non_repeaters: int = 0) -> list[VarBind]:
        if self.version == "1":
            raise ValueError("GETBULK needs SNMP v2c")
        return await self._request(PDU_GETBULK, oids, non_repeaters, max_repetitions)

    async def walk(self, column: str, max_repetitions: int = 10, max_rows: int = 10000) -> list[VarBind]:
        """All rows under `column` (stops at the first OID outside it, like lexicographicMode=False)."""
        prefix = column.strip(".") + "."
        rows: list[VarBind] = []
        current = column.strip(".")
        reps = max_repetitions
        while len(rows) < max_rows:
            try:
                if self.version == "1":
                    batch = await self.getnext([current])
                else:
                    batch = await self.getbulk([current], reps)
            except SnmpErrorStatus as exc:
                if exc.name == "tooBig" and self.version != "1" and reps > 1:
                    reps = max(1, reps // 2)       # answer didn't fit: ask for fewer rows
                    continue
                if exc.name == "noSuchName" and self.version == "1":
                    break                          # v1 end of MIB
                raise
            if not batch:
                break
            done = False
            for vb in batch:
                if vb.type in END_TYPES or not vb.oid.startswith(prefix):
                    done = True
                    break
                rows.append(vb)
            if done:
                break
            nxt = batch[-1].oid
            if nxt == current:
                break                              # agent not advancing: avoid a loop
            current = nxt
        return rows
