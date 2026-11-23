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
        raise BerError("indefinite length is not used by SNMP")
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > limit:
            raise BerError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if length < 0 or pos + length > limit:
        raise BerError("length exceeds data")
    return tag, pos, pos + length


def expect(data: bytes, pos: int, tag: int, end: int | None = None) -> tuple[int, int]:
    """Read a TLV that must have ``tag``. Returns (value_start, value_end)."""
    got, start, end_ = read_tlv(data, pos, end)
    if got != tag:
        raise BerError(f"expected tag {tag:#x}, got {got:#x}")
    return start, end_


def decode_int(data: bytes) -> int:
    if not data:
        raise BerError("empty integer")
    return int.from_bytes(data, "big", signed=True)


def decode_oid(data: bytes) -> str:
    if not data:
        raise BerError("empty OID")
    first = data[0]
    parts = [first // 40, first % 40]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    if val:
        raise BerError("unterminated OID sub-identifier")
    return ".".join(str(p) for p in parts)


def decode_value(tag: int, data: bytes):
    """Turn a BER value into a Python object suitable for JSON and OPC UA."""
    if tag == INTEGER:
        return decode_int(data)
    if tag == OCTET_STRING:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.hex()
    if tag == NULL:
        return None
    if tag == OBJECT_IDENTIFIER:
        return decode_oid(data)
    if tag == IP_ADDRESS and len(data) == 4:
        return str(ipaddress.IPv4Address(data))
    if tag in (COUNTER32, GAUGE32, TIMETICKS):
        return int.from_bytes(data, "big")
    if tag == COUNTER64:
        return int.from_bytes(data, "big")
    if tag in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return None
    return data.hex()


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------
def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(value)) + value


def encode_int(n: int, tag: int = INTEGER) -> bytes:
    if n == 0:
        return tlv(tag, b"\x00")
    # two's complement, minimal length, high bit of first byte is the sign
    length = (n.bit_length() + 8) // 8
    body = n.to_bytes(length, "big", signed=True)
    if body[0] == 0 and len(body) > 1 and not body[1] & 0x80:
        body = body[1:]
    elif body[0] == 0xFF and len(body) > 1 and body[1] & 0x80:
        body = body[1:]
    return tlv(tag, body)


def encode_octets(data: bytes, tag: int = OCTET_STRING) -> bytes:
    return tlv(tag, data)


def encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".") if p]
    if len(parts) < 2:
        raise ValueError("OID needs at least two components")
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            body += bytes([p])
        else:
            tmp = []
            while p:
                tmp.append(p & 0x7F)
                p >>= 7
            tmp[-1] |= 0x80
            body += bytes(reversed(tmp))
    return tlv(OBJECT_IDENTIFIER, body)


def sequence(*items: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(items))
