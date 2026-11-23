"""Minimal BER encoder/decoder for the subset of ASN.1 used by SNMP v1/v2c.

No third-party dependencies. Decoding is bounds-checked so malformed or
hostile packets raise BerError instead of hanging or crashing the gateway.
"""
from __future__ import annotations

import ipaddress
import struct

# Universal tags
INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_IDENTIFIER = 0x06
SEQUENCE = 0x30
# SNMP application tags
IP_ADDRESS = 0x40
COUNTER32 = 0x41
GAUGE32 = 0x42
TIMETICKS = 0x43
OPAQUE = 0x44
COUNTER64 = 0x46
# SNMPv2 exception values (context-specific, primitive)
NO_SUCH_OBJECT = 0x80
NO_SUCH_INSTANCE = 0x81
END_OF_MIB_VIEW = 0x82

# SNMP data type names as used in SNMP agent manuals (e.g. Kepware SNMP Agent Plug-In).
# Unsigned32 and Gauge32 share one wire tag, so it is reported as Gauge32.
TYPE_NAMES = {
    INTEGER: "Integer32",
    OCTET_STRING: "Octet String",
    NULL: "Null",
    OBJECT_IDENTIFIER: "Object Identifier",
    IP_ADDRESS: "IpAddress",
    COUNTER32: "Counter32",
    GAUGE32: "Gauge32",
    TIMETICKS: "TimeTicks",
    OPAQUE: "Opaque",
    COUNTER64: "Counter64",
    NO_SUCH_OBJECT: "NoSuchObject",
    NO_SUCH_INSTANCE: "NoSuchInstance",
    END_OF_MIB_VIEW: "EndOfMibView",
}


class BerError(ValueError):
    """Raised when data is not valid BER for our purposes."""


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------
def read_tlv(data: bytes, pos: int, end: int | None = None) -> tuple[int, int, int]:
    """Read one TLV starting at ``pos``. Returns (tag, value_start, value_end)."""
    limit = len(data) if end is None else end
    if pos + 2 > limit:
        raise BerError("unexpected end of data")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise BerError("multi-byte tags are not used by SNMP")
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise BerError("indefinite length is not allowed in SNMP")
    else:
        n = first & 0x7F
        if n > 4 or pos + n > limit:
            raise BerError("bad long-form length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    value_end = pos + length
    if value_end > limit:
        raise BerError("length runs past end of data")
    return tag, pos, value_end


def expect(data: bytes, pos: int, tag: int, end: int | None = None) -> tuple[int, int]:
    """Read a TLV and check its tag. Returns (value_start, value_end)."""
    got, start, stop = read_tlv(data, pos, end)
    if got != tag:
        raise BerError(f"expected tag 0x{tag:02x}, got 0x{got:02x}")
    return start, stop


def decode_int(content: bytes, signed: bool = True) -> int:
    if not content:
        raise BerError("empty integer")
    if len(content) > 9:
        raise BerError("integer too large")
    return int.from_bytes(content, "big", signed=signed)


def decode_oid(content: bytes) -> str:
    if not content:
        raise BerError("empty OID")
    if content[-1] & 0x80:
        raise BerError("truncated OID")
    arcs: list[int] = []
    value = 0
    for byte in content:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(a) for a in head + arcs[1:])


def _octets_to_text(content: bytes) -> str:
    """Printable text if it looks like text, otherwise colon-separated hex."""
    trimmed = content.rstrip(b"\x00")
    try:
        text = trimmed.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            return text
    except UnicodeDecodeError:
        pass
    return ":".join(f"{b:02x}" for b in content)


def decode_value(tag: int, content: bytes):
    """Decode a varbind value. Returns (type_name, python_value)."""
    name = TYPE_NAMES.get(tag, f"Unknown(0x{tag:02x})")
    if tag == INTEGER:
        return name, decode_int(content)
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return name, decode_int(content, signed=False)
    if tag == OCTET_STRING:
        return name, _octets_to_text(content)
    if tag == OBJECT_IDENTIFIER:
        return name, decode_oid(content)
    if tag == IP_ADDRESS:
        if len(content) != 4:
            raise BerError("IpAddress must be 4 bytes")
        return name, str(ipaddress.IPv4Address(content))
    if tag in (NULL, NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return name, None
    if tag == OPAQUE:
        # net-snmp wraps floats in Opaque: 9f 78 04 <float> / 9f 79 08 <double>
        if len(content) == 7 and content[:3] == b"\x9f\x78\x04":
            return name, struct.unpack(">f", content[3:])[0]
        if len(content) == 11 and content[:3] == b"\x9f\x79\x08":
            return name, struct.unpack(">d", content[3:])[0]
    # Opaque and anything unknown: keep the raw bytes as hex
    return name, content.hex()


# --------------------------------------------------------------------------
# Encoding (used for INFORM acknowledgements and the test trap sender)
# --------------------------------------------------------------------------
def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(content)) + content


def encode_int(value: int, tag: int = INTEGER) -> bytes:
    bits = (~value).bit_length() if value < 0 else value.bit_length()
    length = bits // 8 + 1
    return tlv(tag, value.to_bytes(length, "big", signed=True))


def _base128(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    out = []
    while n:
        out.append(n & 0x7F)
        n >>= 7
    out.reverse()
    return bytes([b | 0x80 for b in out[:-1]] + [out[-1]])


def encode_oid(oid: str) -> bytes:
    arcs = [int(a) for a in oid.strip(".").split(".")]
    if len(arcs) < 2:
        raise ValueError(f"OID needs at least two arcs: {oid!r}")
    body = _base128(arcs[0] * 40 + arcs[1]) + b"".join(_base128(a) for a in arcs[2:])
    return tlv(OBJECT_IDENTIFIER, body)


def encode_octets(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return tlv(OCTET_STRING, value)


def encode_null() -> bytes:
    return b"\x05\x00"


def encode_ip(addr: str) -> bytes:
    return tlv(IP_ADDRESS, ipaddress.IPv4Address(addr).packed)


def sequence(*items: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(items))
