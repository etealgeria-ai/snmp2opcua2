"""Asyncio UDP listener that turns SNMP datagrams into Trap objects on a queue."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import ber
from .oids import OidResolver
from .snmpv3 import SnmpV3Engine, V3Rejected, peek_version
from .trap import UnsupportedMessage, build_inform_response, parse_message
from . import kepware
from .usm import UsmError

log = logging.getLogger("snmp2opcua.receiver")

VERSION_NAMES = {0: "v1", 1: "v2c", 3: "v3"}


@dataclass
class Stats:
    received: int = 0       # valid notifications accepted
    published: int = 0      # delivered to OPC UA
    dropped: int = 0        # queue full or publish failure
    rejected: int = 0       # wrong community/user/key, source or version not allowed
    malformed: int = 0      # undecodable or unsupported packets
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TrapProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue, stats: Stats, resolver: OidResolver,
                 communities: list[str], allowed_sources: list[str], respond_to_informs: bool = True,
                 v3: SnmpV3Engine | None = None, versions: list[str] | None = None, monitor=None,
                 accept_all_hosts: bool | None = None):
        self.queue = queue
        self.stats = stats
        self.resolver = resolver
        self.communities = set(communities or [])
        self.networks = [ipaddress.ip_network(s, strict=False) for s in (allowed_sources or [])]
        # "Accept packets from all hosts": default on when no host list is given
        self.accept_all_hosts = (not self.networks) if accept_all_hosts is None else bool(accept_all_hosts)
        self.respond_to_informs = respond_to_informs
        self.v3 = v3
        self.versions = set(versions or ["v1", "v2c", "v3"])
        self.transport: asyncio.DatagramTransport | None = None
        self.monitor = monitor          # optional callable(kind, payload) for UIs

    def _notify(self, kind: str, payload) -> None:
        if self.monitor is not None:
            try:
                self.monitor(kind, payload)
            except Exception:
                log.debug("monitor callback failed", exc_info=True)

    def connection_made(self, transport):
        self.transport = transport

    def _source_allowed(self, ip: str) -> bool:
        if self.accept_all_hosts:
            return True
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return False
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in net for net in self.networks)

    def _send(self, payload: bytes | None, addr, send=None) -> None:
        if not payload or not self.respond_to_informs:
            return
        try:
            if send is not None:
                send(payload)
            elif self.transport is not None:
                self.transport.sendto(payload, addr)
        except Exception:
            log.exception("Failed to send reply to %s", addr[0])

    def _reject(self, ip: str, reason: str) -> None:
        self.stats.rejected += 1
        log.warning("Rejected packet from %s: %s", ip, reason)
        self._notify("rejected", {"source": ip, "reason": reason})

    def datagram_received(self, data: bytes, addr):
        self.handle(data, addr)

    def handle(self, data: bytes, addr, send=None) -> None:
        """Process one SNMP message (UDP datagram or one message from a TCP stream)."""
        ip = addr[0]
        if not self._source_allowed(ip):
            return self._reject(ip, "source is not in the accepted host list (allowed_sources)")
        try:
            version = VERSION_NAMES.get(peek_version(data), "unknown")
            if version not in self.versions:
                return self._reject(ip, f"SNMP {version} is not enabled (snmp.versions)")
            if version == "v3":
                if self.v3 is None:
                    return self._reject(ip, "SNMPv3 message but no snmp.v3.users are configured")
                try:
                    trap, reply = self.v3.handle(data, addr)
                except V3Rejected as exc:
                    self._send(exc.reply, addr, send)
                    return self._reject(ip, str(exc))
                self._send(reply, addr, send)
                if trap is None:      # engine discovery: the Report was the whole answer
                    return
            else:
                trap = parse_message(data, addr, self.resolver)
                if self.communities and trap.community not in self.communities:
                    return self._reject(ip, f"{trap.pdu} with a community that is not accepted")
                if trap.pdu == "inform":
                    self._send(build_inform_response(data), addr, send)
            kepware.annotate(trap)
        except (ber.BerError, UnsupportedMessage, UsmError) as exc:
            self.stats.malformed += 1
            log.warning("Ignored packet from %s: %s", ip, exc)
            self._notify("malformed", {"source": ip, "reason": str(exc)})
            return
        except Exception as exc:  # never let one bad packet kill the listener
            self.stats.malformed += 1
            log.exception("Unexpected error decoding packet from %s", ip)
            self._notify("malformed", {"source": ip, "reason": f"unexpected error: {exc}"})
            return

        self.stats.received += 1
        log.info("%s", trap.summary())
        self._notify("trap", trap)
        try:
            self.queue.put_nowait(trap)
        except asyncio.QueueFull:
            self.stats.dropped += 1
            log.error("Queue full, dropped trap from %s (%s)", ip, trap.trap_name)

    def error_received(self, exc):
        log.warning("UDP socket error: %s", exc)


class TrapTcpProtocol(asyncio.Protocol):
    """SNMP over TCP (RFC 3430): BER messages back to back on one connection."""

    MAX_MESSAGE = 65535

    def __init__(self, core: TrapProtocol):
        self.core = core
        self.buf = bytearray()
        self.transport: asyncio.Transport | None = None
        self.peer = ("?", 0)

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername") or ("?", 0)

    @staticmethod
    def message_length(buf: bytes) -> int | None:
        """Total length of the BER message at the start of buf, or None if the header is incomplete."""
        if len(buf) < 2:
            return None
        if buf[0] != ber.SEQUENCE:
            raise ber.BerError("not an SNMP message")
        first = buf[1]
        if first < 0x80:
            return 2 + first
        n = first & 0x7F
        if n == 0 or n > 4:
            raise ber.BerError("bad length")
        if len(buf) < 2 + n:
            return None
        return 2 + n + int.from_bytes(buf[2:2 + n], "big")

    def data_received(self, data: bytes):
        transport = self.transport
        if transport is None:
            return
        self.buf += data
        while True:
            try:
                total = self.message_length(bytes(self.buf[:6]))
            except ber.BerError:
                self.core._reject(self.peer[0], "not an SNMP message on the TCP trap port")
                transport.close()
                return
            if total is None or len(self.buf) < total:
                return                       # wait for the rest
            if total > self.MAX_MESSAGE:
                self.core._reject(self.peer[0], "SNMP message over TCP is too large")
                transport.close()
                return
            msg = bytes(self.buf[:total])
            del self.buf[:total]
            self.core.handle(msg, self.peer, send=transport.write)


class ListenerError(OSError):
    """A trap listener could not be started (message worded like the SNMP driver's)."""


async def start_listener(loop: asyncio.AbstractEventLoop, host: str, port: int, protocol_factory,
                         protocol: str = "UDP"):
    try:
        if protocol == "TCP":
            core = protocol_factory()
            server = await loop.create_server(lambda: TrapTcpProtocol(core), host, port)
            log.info("Listening for SNMP traps on tcp://%s:%d", host, port)
            return server
        transport, _ = await loop.create_datagram_endpoint(protocol_factory, local_addr=(host, port))
        log.info("Listening for SNMP traps on udp://%s:%d", host, port)
        return transport
    except PermissionError as exc:
        raise ListenerError(exc.errno, f"Unable to bind trap socket on binding address {host}, port {port} and "
                                       f"protocol {protocol}: permission denied. Ports below 1024 need "
                                       f"administrator/root rights; run as administrator or use a port above "
                                       f"1024.") from exc
    except OSError as exc:
        raise ListenerError(exc.errno, f"Unable to bind trap socket on binding address {host}, port {port} and "
                                       f"protocol {protocol}. Another application may already be bound to it: "
                                       f"close it (e.g. snmptrapd, or make sure the Windows SNMP Trap service "
                                       f"is not running) or select a different address or port. ({exc.strerror or exc})"
                            ) from exc
