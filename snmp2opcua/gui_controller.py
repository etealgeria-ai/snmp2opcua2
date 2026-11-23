"""Thread-safe bridge between the desktop window and the gateway.

The gateway runs in its own thread with its own asyncio loop. Everything it reports
(traps, rejections, log lines, start/stop) goes into ``events``, a plain
``queue.Queue`` that the Tk main loop drains, because Tk may only be touched from
its own thread. Nothing in this module imports tkinter, so it can be tested headless.
"""
from __future__ import annotations

import asyncio
import logging
import os
import queue
import shutil
import socket
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .config import load_config
from .gateway import Gateway
from .severity import SeverityMap
from .usm import UsmUser

log = logging.getLogger("snmp2opcua.gui")


class QueueLogHandler(logging.Handler):
    """Forward log records to the UI event queue."""

    def __init__(self, events: queue.Queue):
        super().__init__(level=logging.INFO)
        self.events = events
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.events.put(("log", (record.levelname, self.format(record))))
        except Exception:
            pass


@dataclass
class TrapRequest:
    """Parameters for the Send test trap form."""
    host: str = "127.0.0.1"
    port: int = 162
    version: str = "2c"              # "1", "2c" or "3"
    trap_oid: str = "linkDown"
    varbinds: str = ""               # one "OID TYPE VALUE" per line
    inform: bool = False
    community: str = "public"
    user: UsmUser | None = None      # v3: a configured user, or one built from custom fields


def severity_label(sev: int) -> str:
    if sev >= 800:
        return "High"
    if sev >= 600:
        return "Medium"
    return "Low"


def parse_varbind_lines(text: str) -> list[tuple[str, str, str]]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2 or (len(parts) == 2 and parts[1] != "n"):
            raise ValueError(f"Varbind line {n}: use 'OID TYPE VALUE', e.g. 'ifIndex.3 i 3'")
        if parts[1] not in "iucCtaosxn" or len(parts[1]) != 1:
            raise ValueError(f"Varbind line {n}: unknown type {parts[1]!r} (use i u c C t a o s x n)")
        out.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))
    return out


class GatewayController:
    def __init__(self, config_path: str | os.PathLike):
        self.config_path = Path(config_path)
        self.events: queue.Queue = queue.Queue()
        self.cfg: dict | None = None
        self.severity = SeverityMap()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._gateway: Gateway | None = None
        self.started_at: datetime | None = None
        self.publisher_factory = None      # tests can inject a fake OPC UA publisher
        self.trap_times: deque[float] = deque(maxlen=20000)   # monotonic receive times, for rates
        self.last_trap_at: datetime | None = None
        self.kepware_agents: dict[tuple[str, int | None], tuple[str, str]] = {}   # (ip, agent) -> (time, descr)
        self.log_handler = QueueLogHandler(self.events)
        root = logging.getLogger()
        if self.log_handler not in root.handlers:
            root.addHandler(self.log_handler)
        if root.level > logging.INFO or root.level == logging.NOTSET:
            root.setLevel(logging.INFO)
        logging.getLogger("asyncua").setLevel(logging.WARNING)

    def close(self) -> None:
        """Detach from logging (call when the window closes)."""
        logging.getLogger().removeHandler(self.log_handler)

    # ------------------------------------------------------------------ config
    def load(self) -> dict:
        self.cfg = load_config(self.config_path)
        self.severity = SeverityMap(self.cfg["traps"]["severity"])
        return self.cfg

    def read_text(self) -> str:
        return self.config_path.read_text(encoding="utf-8")

    @staticmethod
    def validate_text(text: str) -> dict:
        """Parse and validate YAML text the same way the gateway will. Raises ValueError."""
        fd, tmp = tempfile.mkstemp(suffix=".yaml")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            try:
                return load_config(tmp)
            except ValueError:
                raise
            except Exception as exc:   # YAML syntax errors etc.
                raise ValueError(str(exc)) from exc
        finally:
            os.unlink(tmp)

    def save_text(self, text: str) -> None:
        """Validate, back up the old file to <name>.bak, then write."""
        self.validate_text(text)
        if self.config_path.exists():
            shutil.copy2(self.config_path, self.config_path.with_suffix(self.config_path.suffix + ".bak"))
        self.config_path.write_text(text, encoding="utf-8")

    # ------------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        cfg = self.load()                  # raises on bad config: let the UI show it
        self._thread = threading.Thread(target=self._run, args=(cfg,), name="gateway", daemon=True)
        self._thread.start()

    def _run(self, cfg: dict) -> None:
        try:
            asyncio.run(self._main(cfg))
        except Exception as exc:
            self.events.put(("error", self._explain(exc, cfg)))
        finally:
            self._loop = None
            self._gateway = None
            self.started_at = None
            self.events.put(("stopped", None))

    async def _main(self, cfg: dict) -> None:
        self._loop = asyncio.get_running_loop()
        self._gateway = Gateway(cfg, publisher=self.publisher_factory() if self.publisher_factory else None)
        self._gateway.monitor = self._monitor
        await self._gateway.run()

    @staticmethod
    def _explain(exc: BaseException, cfg: dict) -> str:
        from .receiver import ListenerError
        if isinstance(exc, ListenerError):
            return exc.strerror or str(exc)
        port = cfg["snmp"]["listen_port"]
        if isinstance(exc, PermissionError):
            return (f"No permission to listen on UDP port {port}. Run as administrator/root, "
                    f"or use a port above 1024 in the configuration.")
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in (98, 10048, 48):
            return (f"UDP port {port} is already in use. Stop the other trap receiver "
                    f"(snmptrapd, or the Windows 'SNMP Trap' service) or choose another port.")
        if isinstance(exc, SystemExit):
            return str(exc)
        return f"{type(exc).__name__}: {exc}"

    def _monitor(self, kind: str, payload) -> None:
        """Called from the gateway thread."""
        if kind == "started":
            self.started_at = datetime.now()
            payload = dict(payload, mode=self.cfg["opcua"]["mode"] if self.cfg else "",
                           opcua=self._opcua_target())
            self.events.put(("started", payload))
        elif kind == "trap":
            self.trap_times.append(time.monotonic())
            self.last_trap_at = datetime.now()
            d = payload.to_dict()
            sev = self.severity.for_trap(payload)
            d["severity"] = sev
            d["severity_label"] = severity_label(sev)
            d["time"] = payload.received_at.astimezone().strftime("%H:%M:%S")
            if d.get("vendor"):
                self.kepware_agents[(d["source_ip"], d.get("agent_id"))] = (d["time"], d.get("description", ""))
            self.events.put(("trap", d))
        elif kind == "tags":
            self.events.put(("tags", list(payload)))
        elif kind == "radios":
            self.events.put(("radios", dict(payload)))
        elif kind == "catalog":
            self.events.put(("catalog", list(payload)))
        else:
            payload = dict(payload, time=datetime.now().strftime("%H:%M:%S"))
            self.events.put((kind, payload))

    def _opcua_target(self) -> str:
        if not self.cfg:
            return ""
        o = self.cfg["opcua"]
        return o["server"]["endpoint"] if o["mode"] == "server" else o["client"]["url"]

    def stop(self, timeout: float = 10.0) -> None:
        loop, gw, thread = self._loop, self._gateway, self._thread
        if loop is not None and gw is not None:
            try:
                loop.call_soon_threadsafe(gw.stop)
            except RuntimeError:
                pass   # loop already closed
        if thread is not None:
            thread.join(timeout)

    def stats(self) -> dict:
        gw = self._gateway
        if gw is None:
            return {}
        s = gw.stats
        try:
            queued = gw.queue.qsize()
        except Exception:
            queued = 0
        return {"received": s.received, "published": s.published, "queued": queued,
                "rejected": s.rejected, "malformed": s.malformed, "dropped": s.dropped}

    def snapshot(self) -> dict:
        """Runtime state for the diagnostics page, collected safely inside the gateway's thread."""
        loop, gw = self._loop, self._gateway
        if loop is None or gw is None:
            return {}

        async def collect() -> dict:
            v3 = gw.v3
            pub = gw.publisher
            return {
                "queue": gw.queue.qsize(), "queue_max": gw.queue.maxsize,
                "v3": None if v3 is None else {
                    "engine_id": v3.engine_id.hex(), "boots": v3.boots, "engine_time": v3.engine_time(),
                    "counters": dict(v3.counters), "remote": v3.remote_engines(),
                    "replay_protection": v3.replay_protection},
                "publisher": pub.diagnostics() if hasattr(pub, "diagnostics") else {},
                "devices": [{
                    "path": d.path, "host": d.host, "resolved": st.resolved, "error": st.error,
                    "enabled": d.trap_enabled, "version": d.snmp_version, "port": d.port, "protocol": d.protocol,
                    "community": bool(d.community), "count": st.count, "ignored": st.ignored,
                    "last_reason": st.last_reason,
                    "last_trap": st.last_trap.astimezone().strftime("%H:%M:%S") if st.last_trap else None}
                    for d in gw.engine.devices for st in [gw.engine.state[d.path]]],
                "unmatched": dict(gw.engine.unmatched),
                "polling": [{
                    "path": p.dev.path, "host": p.dev.host, "port": p.cfg.port, "version": p.cfg.version,
                    "rate_ms": p.cfg.scan_rate_ms, "orbit": p.cfg.ge_orbit_remotes, "tags": len(p.tags),
                    "polls": p.stats.polls, "failures": p.stats.failures,
                    "consecutive_failures": p.stats.consecutive_failures, "error": p.stats.last_error,
                    "duration_ms": p.stats.duration_ms, "timeouts": p.client.timeouts,
                    "last_ok": p.stats.last_ok.astimezone().strftime("%H:%M:%S") if p.stats.last_ok else None,
                    "rssi_warning": p.cfg.rssi_warning_dbm, "radios": p.radios(),
                    "remote_tags": p.cfg.remote_tags, "prefix": p.cfg.remote_tag_prefix,
                    "slots": dict(p.slots), "overflow": list(p.overflow)} for p in gw.pollers],
            }
        try:
            return asyncio.run_coroutine_threadsafe(collect(), loop).result(timeout=3)
        except Exception:
            return {}

    def trap_rate(self, seconds: float) -> int:
        cutoff = time.monotonic() - seconds
        return sum(1 for t in reversed(self.trap_times) if t >= cutoff) if self.trap_times else 0

    # ------------------------------------------------------------------ test traps
    def configured_users(self) -> list[UsmUser]:
        if not self.cfg:
            return []
        return list(self.cfg["snmp"]["v3"].get("_users") or [])

    def send_test_trap(self, t: TrapRequest) -> str:
        """Blocking (an inform waits for its acknowledgement): call from a worker thread."""
        from . import sendtrap as st
        vbs = [st.varbind(oid, st.encode_typed(kind, value)) for oid, kind, value in parse_varbind_lines(t.varbinds)]
        uptime = int(time.monotonic() * 100) & 0xFFFFFFFF
        family = socket.AF_INET6 if ":" in t.host else socket.AF_INET
        addr = (t.host, int(t.port))
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            if t.version == "3":
                if t.user is None:
                    raise ValueError("Choose an SNMPv3 user")
                if t.inform:
                    return st.send_v3_inform(sock, addr, t.user, t.trap_oid, uptime, vbs)
                pkt = st.build_v3(t.user, bytes.fromhex(st.DEFAULT_V3_ENGINE_ID), 1, int(time.time()) & 0x7FFFFFFF,
                                  t.trap_oid, uptime, vbs)
                sock.sendto(pkt, addr)
                return f"Sent SNMPv3 trap ({t.user.level}, user {t.user.name}) to {t.host}:{t.port}"
            if t.version == "1":
                if t.inform:
                    raise ValueError("SNMPv1 has no informs; choose v2c or v3")
                pkt = st.build_v1(t.community, "1.3.6.1.4.1.8072.3.2.10", "127.0.0.1", 6, 1, uptime, vbs)
                sock.sendto(pkt, addr)
                return f"Sent SNMPv1 trap to {t.host}:{t.port}"
            pkt = st.build_v2(t.community, t.trap_oid, uptime, vbs, inform=t.inform)
            sock.sendto(pkt, addr)
            if not t.inform:
                return f"Sent SNMPv2c trap to {t.host}:{t.port}"
            try:
                sock.recvfrom(65535)
            except socket.timeout:
                raise ValueError("No acknowledgement within 3 s. Is the gateway running and the community "
                                 "accepted?") from None
            return "Inform acknowledged"
