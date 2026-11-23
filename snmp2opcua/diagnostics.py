"""Health checks for the desktop window's Diagnostics tab.

Each check returns a status (ok, warn, problem, info), what was found, and, when
something is wrong, how to fix it. Nothing here imports tkinter, so it can be tested
headless. Network checks have short timeouts, but call ``run_diagnostics`` from a worker
thread anyway.
"""
from __future__ import annotations

import errno
import os
import platform
import socket
import sys
from dataclasses import dataclass
from datetime import datetime
from importlib import metadata
from pathlib import Path
from urllib.parse import urlsplit

from .snmp_driver import PollAddress

STATUS_LABEL = {"problem": "Problem", "warn": "Warning", "ok": "OK", "info": "Info"}
STATUS_ORDER = ["problem", "warn", "ok", "info"]

# What each SNMPv3 USM counter means for the person looking at it
USM_EXPLAIN = {
    "unknownUserNames": ("Messages from an unknown SNMPv3 user",
                         "Add the user under snmp.v3.users, or fix the user name on the device."),
    "wrongDigests": ("Messages that failed authentication",
                     "The device's auth key or auth protocol doesn't match the user's settings here."),
    "decryptionErrors": ("Messages that couldn't be decrypted",
                         "The priv key or priv protocol doesn't match. For AES-192/256, try the other "
                         "variant (AES256 vs AES256C)."),
    "unsupportedSecLevels": ("Messages at the wrong security level",
                             "The device sends at a different level (e.g. authNoPriv) than the user is "
                             "configured for. Make both sides match."),
    "notInTimeWindows": ("Stale or replayed messages",
                         "Usually a device that resets its engine boots counter on reboot. Fix the device, "
                         "or set snmp.v3.replay_protection: false."),
    "unknownEngineIDs": ("Engine discovery requests answered",
                         ""),   # normal: every inform sender does this first
}


@dataclass
class Check:
    section: str
    name: str
    status: str          # problem / warn / ok / info
    result: str
    hint: str = ""

    @property
    def label(self) -> str:
        return STATUS_LABEL[self.status]


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------
def udp_port_status(host: str, port: int) -> tuple[str, str]:
    """('free' | 'in_use' | 'no_permission' | 'bad_address', detail) by trying to bind."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.bind((host, port))
        return "free", ""
    except PermissionError as exc:
        return "no_permission", str(exc)
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, 10048):
            return "in_use", str(exc)
        return "bad_address", str(exc)
    finally:
        s.close()


def tcp_port_status(host: str, port: int) -> tuple[str, str]:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        if sys.platform != "win32":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        return "free", ""
    except PermissionError as exc:
        return "no_permission", str(exc)
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, 10048):
            return "in_use", str(exc)
        return "bad_address", str(exc)
    finally:
        s.close()


def tcp_reachable(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except socket.timeout:
        return False, f"no answer within {timeout:g} s"
    except OSError as exc:
        return False, exc.strerror or str(exc)


def parse_opc_url(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    if parts.scheme != "opc.tcp" or not parts.hostname:
        raise ValueError(f"not an opc.tcp:// URL: {url!r}")
    return parts.hostname, parts.port or 4840


def local_addresses() -> list[str]:
    """IPv4 addresses of this machine that devices could send traps to."""
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(str(info[4][0]))
    except OSError:
        pass
    try:  # the address used for the default route; connect() on UDP sends nothing
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            found.add(s.getsockname()[0])
    except OSError:
        pass
    real = sorted(a for a in found if not a.startswith("127."))
    return real or sorted(found)


def package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def is_admin() -> bool | None:
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


def _n(count: int, word: str) -> str:
    return f"{count:,} {word}{'' if count == 1 else 's'}"


def _ago(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    return f"{seconds // 3600} h {seconds % 3600 // 60} min ago"


def _writable_location(path: Path) -> bool:
    if path.exists():
        return os.access(path, os.W_OK)
    parent = path.parent if str(path.parent) else Path(".")
    return parent.exists() and os.access(parent, os.W_OK)


# --------------------------------------------------------------------------
# The checks
# --------------------------------------------------------------------------
def run_diagnostics(ctl, tk_version: str | None = None) -> list[Check]:
    """Run every check against a GatewayController (running or not)."""
    out: list[Check] = []

    def add(section, name, status, result, hint=""):
        out.append(Check(section, name, status, result, hint))

    running = ctl.running
    snap = ctl.snapshot() if running else {}

    # ---------------------------------------------------------------- configuration
    sec = "Configuration"
    path = Path(ctl.config_path)
    if not path.exists():
        add(sec, "Config file", "problem", f"{path} does not exist",
            "Open a configuration with Open config…, or create config.yaml from the example in the README.")
        cfg = None
    else:
        add(sec, "Config file", "ok", str(path.resolve()))
        try:
            cfg = ctl.cfg if running and ctl.cfg else ctl.load()
            add(sec, "Configuration", "ok", "Loads and passes validation")
        except Exception as exc:
            cfg = None
            add(sec, "Configuration", "problem", str(exc),
                "Fix it in the Configuration tab. Use Check to see if it's valid before saving.")

    if cfg is not None:
        snmp, opc = cfg["snmp"], cfg["opcua"]
        add(sec, "SNMP versions accepted", "info", ", ".join(snmp["versions"]))
        users = snmp["v3"].get("_users") or []
        if "v3" in snmp["versions"]:
            if users:
                add(sec, "SNMPv3 users", "ok", ", ".join(f"{u.name} ({u.level})" for u in users))
            else:
                add(sec, "SNMPv3 users", "warn", "v3 is accepted but no users are configured, so every v3 "
                    "message will be rejected", "Add users under snmp.v3.users, or remove v3 from snmp.versions.")

    # ---------------------------------------------------------------- SNMP listener
    sec = "SNMP listener"
    if cfg is not None:
        from .config import listen_endpoints
        host, port = snmp["listen_host"], int(snmp["listen_port"])
        endpoints = listen_endpoints(cfg)
        for ep_host, ep_port, proto in endpoints:
            label = "UDP port" if len(endpoints) == 1 else f"{proto} {ep_host}:{ep_port}"
            if running:
                add(sec, label, "ok", f"This gateway is listening on {proto} {ep_host}:{ep_port}")
                continue
            state, detail = (udp_port_status if proto == "UDP" else tcp_port_status)(ep_host, ep_port)
            if state == "free":
                add(sec, label, "ok", f"{proto} {ep_host}:{ep_port} is free; the gateway can listen there")
            elif state == "in_use":
                add(sec, label, "problem", f"{ep_host}:{ep_port} ({proto}) is already in use by another program",
                    "Unable to bind trap socket: close the other application (e.g. snmptrapd), make sure the "
                    "Windows SNMP Trap service is not running, or select a different address or port.")
            elif state == "no_permission":
                add(sec, label, "problem", f"Not allowed to listen on port {ep_port}",
                    "Ports below 1024 need administrator/root rights (Linux: CAP_NET_BIND_SERVICE). "
                    "Run as administrator, or use a port such as 1162.")
            else:
                add(sec, label, "problem", f"Can't listen on {ep_host}:{ep_port}: {detail}",
                    "listen_host must be an address of this machine, or 0.0.0.0 for all of them.")
        addrs = local_addresses()
        if host.startswith("127.") or host in ("::1", "localhost"):
            add(sec, "Listen address", "warn", f"{host} accepts traps from this computer only",
                "Set snmp.listen_host to 0.0.0.0 so network devices can reach the gateway.")
        else:
            scope = "all interfaces" if host in ("0.0.0.0", "::") else "one interface"
            add(sec, "Listen address", "ok", f"{host} ({scope})")
        if addrs:
            add(sec, "Send traps to", "info", ", ".join(f"{a}:{port}" for a in addrs),
                "Configure these as the trap destination on your devices. Check that the firewall allows "
                f"UDP {port} inbound.")
        accept_all = snmp.get("accept_all_hosts")
        if accept_all is None:
            accept_all = not snmp["allowed_sources"]
        if accept_all:
            add(sec, "Accepted hosts", "info", "Packets are accepted from all hosts",
                "Set accept_all_hosts: false and list your devices under snmp.allowed_sources for extra safety.")
        elif snmp["allowed_sources"]:
            add(sec, "Accepted hosts", "ok", ", ".join(map(str, snmp["allowed_sources"])))
        else:
            add(sec, "Accepted hosts", "problem", "accept_all_hosts is off and no host is listed, so every trap "
                "is rejected", "Add the device addresses under snmp.allowed_sources, or set accept_all_hosts: true.")
        if {"v1", "v2c"} & set(snmp["versions"]):
            comm = snmp["communities"]
            if not comm:
                add(sec, "Communities", "warn", "Any community string is accepted",
                    "List the communities your devices use under snmp.communities.")
            elif "public" in comm:
                add(sec, "Communities", "warn", "The default community 'public' is accepted",
                    "Use a community string of your own on devices and in snmp.communities.")
            else:
                add(sec, "Communities", "ok", f"{len(comm)} configured")

    # ---------------------------------------------------------------- devices (trap tags)
    sec = "Devices"
    if cfg is not None:
        devices = cfg.get("_devices") or []
        if not devices:
            add(sec, "Devices", "info", "No channels or devices configured; traps are still published under "
                "Gateway/LastTrap and as events", "Add channels and devices to get trap tags such as "
                "Channel1.Switch1.linkDown (see the README).")
        else:
            n_tags = sum(len(d.tags) for d in devices)
            add(sec, "Channels / devices / tags", "info",
                f"{len({d.channel for d in devices})} / {len(devices)} / {n_tags:,}")
        live = {d["path"]: d for d in snap.get("devices") or []}
        for dev in devices:
            st = live.get(dev.path)
            name = f"Device {dev.path}"
            if not dev.trap_enabled:
                add(sec, name, "info", "Trap/Inform support is disabled for this device")
                continue
            if st and st["error"]:
                add(sec, name, "problem", st["error"], "Use the device's IP address, or fix host name resolution.")
                continue
            sec_txt = f"v3 user {dev.v3_user.name}" if dev.v3_user else (
                "Custom Community" if dev.community else "any community")
            where = f"{dev.host}, SNMP v{dev.snmp_version}, {sec_txt}, {dev.protocol} {dev.port}"
            if not running or st is None:
                add(sec, name, "info", where)
            elif st["ignored"] and not st["count"]:
                add(sec, name, "warn", f"{where}: {_n(st['ignored'], 'trap')} ignored, none accepted. Last reason: "
                    f"{st['last_reason']}", "Make the device's SNMP version, community or v3 user match what "
                    "the device actually sends.")
            elif st["count"]:
                extra = f"; {st['ignored']} ignored ({st['last_reason']})" if st["ignored"] else ""
                add(sec, name, "warn" if st["ignored"] else "ok",
                    f"{where}: {_n(st['count'], 'trap')}, last at {st['last_trap']}{extra}",
                    "Some traps from this address don't match the device settings." if st["ignored"] else "")
            else:
                add(sec, name, "info", f"{where}: no traps yet",
                    "Configure the device to send traps to this computer's address and port.")
        for ip, n in sorted((snap.get("unmatched") or {}).items(), key=lambda kv: -kv[1])[:10]:
            if devices:
                add(sec, f"Traps from {ip}", "warn", f"{_n(n, 'trap')} from an address that isn't a configured device",
                    "They're still published under Gateway/LastTrap. To get trap tags, add a device with "
                    f"ip: {ip}.")
        for (ip, agent), (when, descr) in sorted(ctl.kepware_agents.items(), key=lambda kv: str(kv[0])):
            add(sec, f"Kepware SNMP Agent at {ip}", "info",
                f"agent sub-identifier {agent if agent is not None else '?'}, last trap {when}"
                + (f": {descr}" if descr else ""))

    # ---------------------------------------------------------------- polling
    sec = "Polling"
    if cfg is not None:
        pollers = [d for d in cfg.get("_devices") or [] if d.poll is not None and d.poll.enabled]
        live_polls = {p["path"]: p for p in snap.get("polling") or []}
        for dev in pollers:
            pc = dev.poll
            assert pc is not None
            n_tags = sum(1 for t in dev.tags if isinstance(t.address, PollAddress))
            parts = ["GE Orbit remotes"] if pc.ge_orbit_remotes else []
            if n_tags:
                parts.append(_n(n_tags, "polled tag"))
            what = " and ".join(parts) or "nothing to poll"
            where = f"{dev.host}:{pc.port}, SNMP v{pc.version}, every {pc.scan_rate_ms / 1000:g} s, {what}"
            lp = live_polls.get(dev.path)
            name = f"Poll {dev.path}"
            if not running or lp is None:
                add(sec, name, "info", where)
                continue
            if lp["polls"] == 0:
                add(sec, name, "info", f"{where}: first poll pending")
            elif lp["consecutive_failures"]:
                add(sec, name, "problem", f"{where}: failing ({lp['error']}); last good poll "
                    f"{lp['last_ok'] or 'never'}",
                    "Check the IP address and read community, that the master allows SNMP from this computer "
                    "(SNMP access list), and that UDP 161 is open between them. Polled tags keep their last "
                    "value with Bad quality meanwhile.")
            else:
                extra = f"; {lp['failures']} failed polls, {lp['timeouts']} timeouts so far" if lp["failures"] else ""
                add(sec, name, "warn" if lp["failures"] else "ok",
                    f"{where}: last poll {lp['last_ok']} took {lp['duration_ms']} ms{extra}",
                    "Occasional timeouts: raise timeout_ms or retries, or check the link to the master."
                    if lp["failures"] else "")
            radios = lp["radios"]
            if pc.ge_orbit_remotes and lp["polls"]:
                offline = [r for r in radios if not r["online"]]
                add(sec, f"Remotes of {dev.path}", "warn" if offline else ("ok" if radios else "info"),
                    f"{len(radios) - len(offline)} online, {len(offline)} offline" if radios else
                    "The master reports no connected remotes",
                    ("Offline: " + ", ".join(f"{r['mac']} ({r['ip']}, last seen {r['last_seen']})" for r in offline))
                    if offline else ("Check that the remotes are powered and associated with this master."
                                     if not radios else ""))
                if lp["remote_tags"]:
                    used = sorted(lp["slots"])
                    span = f" ({lp['prefix']}{used[0]}…{lp['prefix']}{used[-1]})" if used else ""
                    add(sec, f"RSSI tags of {dev.path}", "warn" if lp["overflow"] else "ok",
                        f"{len(used)} of {lp['remote_tags']} {lp['prefix']}N tags in use{span}"
                        + (f"; {len(lp['overflow'])} remotes have no tag" if lp["overflow"] else ""),
                        (f"No {lp['prefix']}N tag for: {', '.join(lp['overflow'])}. Raise remote_tags in the "
                         "Stations page.") if lp["overflow"] else "")
                weak = sorted((r for r in radios if r["online"] and r["weak"]), key=lambda r: r["rssi"])
                if weak:
                    add(sec, f"Weak signal on {dev.path}", "warn",
                        ", ".join(f"{r['mac']} {r['rssi']} dBm" for r in weak),
                        f"These remotes are below rssi_warning_dbm ({pc.rssi_warning_dbm} dBm). Check antennas, "
                        "cabling, alignment and obstructions.")
                if radios:
                    rs = [r["rssi"] for r in radios if r["online"] and r["rssi"] is not None]
                    if rs:
                        add(sec, f"RSSI range on {dev.path}", "info", f"strongest {max(rs)} dBm, weakest {min(rs)} dBm")

    # ---------------------------------------------------------------- SNMPv3
    sec = "SNMPv3"
    if cfg is not None and "v3" in snmp["versions"] and (snmp["v3"].get("_users") or []):
        sf = snmp["v3"].get("state_file")
        if sf:
            if _writable_location(Path(sf)):
                add(sec, "Engine state file", "ok", str(Path(sf).resolve()))
            else:
                add(sec, "Engine state file", "warn", f"{sf} is not writable",
                    "The engine boots counter can't be saved, so inform senders may need to resync after "
                    "a restart. Point snmp.v3.state_file at a writable location.")
        v3 = snap.get("v3")
        if v3:
            add(sec, "Engine ID", "info", v3["engine_id"],
                "Inform senders discover this automatically. Enter it on devices that ask for the "
                "receiver's engine ID.")
            add(sec, "Engine boots / time", "info", f"boots {v3['boots']}, running for {v3['engine_time']} s")
            add(sec, "Replay protection", "ok" if v3["replay_protection"] else "warn",
                "On" if v3["replay_protection"] else "Off: replayed traps would be accepted",
                "" if v3["replay_protection"] else "Turn it back on once devices keep their boots counter.")
            for key, (label, hint) in USM_EXPLAIN.items():
                n = v3["counters"].get(key, 0)
                if key == "unknownEngineIDs":
                    if n:
                        add(sec, label, "info", f"{n:,} (normal: inform senders do this first)")
                    continue
                add(sec, label, "warn" if n else "ok", f"{n:,}", hint if n else "")
            remote = v3["remote"]
            if remote:
                for r in remote[:20]:
                    add(sec, f"Device engine {r['engine_id']}", "info",
                        f"boots {r['boots']}, engine time {r['engine_time']} s, last trap {_ago(r['seen_ago'])}")
            else:
                add(sec, "Device engines", "info", "No authenticated SNMPv3 traps received yet")
        elif not running:
            add(sec, "Engine", "info", "Start the gateway to see its engine ID, counters and devices")

    # ---------------------------------------------------------------- OPC UA
    sec = "OPC UA"
    if cfg is not None:
        asyncua_v = package_version("asyncua")
        if asyncua_v:
            add(sec, "asyncua library", "ok", f"version {asyncua_v}")
        else:
            add(sec, "asyncua library", "problem", "Not installed, so the gateway can't start",
                "Run: pip install -r requirements.txt")
        pub = snap.get("publisher") or {}
        if opc["mode"] == "server":
            ep = opc["server"]["endpoint"]
            try:
                h, p = parse_opc_url(ep)
            except ValueError as exc:
                add(sec, "Endpoint", "problem", str(exc), "Use a URL like opc.tcp://0.0.0.0:4840/snmp2opcua/")
            else:
                if running:
                    probe = "127.0.0.1" if h in ("0.0.0.0", "::") else h
                    ok, why = tcp_reachable(probe, p, 2)
                    add(sec, "OPC UA server", "ok" if ok else "problem",
                        f"Accepting connections on {ep}" if ok else f"Not reachable on {probe}:{p}: {why}",
                        "" if ok else "Check the Log tab for OPC UA server errors.")
                    if pub:
                        add(sec, "Device nodes", "warn" if pub.get("devices", 0) >= pub.get("max_devices", 1 << 30)
                            else "info", f"{pub.get('devices', 0)} of max {pub.get('max_devices')}",
                            "Raise opcua.server.max_devices if more devices should get their own nodes."
                            if pub.get("devices", 0) >= pub.get("max_devices", 1 << 30) else "")
                else:
                    state, detail = tcp_port_status(h, p)
                    if state == "free":
                        add(sec, "OPC UA server port", "ok", f"TCP {p} is free; the server can start on {ep}")
                    elif state == "in_use":
                        add(sec, "OPC UA server port", "problem", f"TCP {p} is already in use",
                            "Another OPC UA server is using it. Change the port in opcua.server.endpoint.")
                    else:
                        add(sec, "OPC UA server port", "problem", f"Can't use {h}:{p}: {detail}",
                            "Use 0.0.0.0 or an address of this machine in opcua.server.endpoint.")
            pols = opc["server"].get("security_policies") or ["NoSecurity"]
            if pols == ["NoSecurity"] or "NoSecurity" in pols:
                add(sec, "Security", "warn", "NoSecurity is allowed, so OPC UA traffic is unencrypted",
                    "For production use Basic256Sha256_SignAndEncrypt with a certificate (see README).")
            else:
                add(sec, "Security", "ok", ", ".join(pols))
            add(sec, "Clients connect to", "info",
                ", ".join(ep.replace(h, a, 1) for a in local_addresses()) if h in ("0.0.0.0", "::") else ep)
        else:
            url = opc["client"]["url"]
            try:
                h, p = parse_opc_url(url)
            except ValueError as exc:
                add(sec, "Server URL", "problem", str(exc), "Use a URL like opc.tcp://192.168.1.50:4840")
            else:
                ok, why = tcp_reachable(h, p, 3)
                add(sec, "Target server", "ok" if ok else "problem",
                    f"{h}:{p} accepts TCP connections" if ok else f"Can't reach {h}:{p}: {why}",
                    "" if ok else "Check the URL, that the OPC UA server is running, and firewalls between "
                    "this machine and the server.")
            if pub:
                add(sec, "Session", "ok" if pub.get("connected") else "problem",
                    f"Connected, writing {pub.get('targets')} nodes" if pub.get("connected") else
                    "Not connected; traps are waiting in the queue",
                    "" if pub.get("connected") else "See the last error below and the Log tab.")
                if pub.get("targets", 0) < pub.get("configured_nodes", 0):
                    add(sec, "Target nodes", "warn", f"{pub.get('targets')} of {pub.get('configured_nodes')} "
                        "configured nodes could be resolved", "Check the NodeIds under opcua.client.nodes.")
                add(sec, "Write errors", "warn" if pub.get("write_errors") else "ok", f"{pub.get('write_errors', 0):,}",
                    "A node refused a write (wrong data type or no write access). See the last error."
                    if pub.get("write_errors") else "")
                if pub.get("last_error"):
                    add(sec, "Last error", "info", f"{pub.get('last_error_at')}: {pub['last_error']}")
                add(sec, "Connections made", "info", f"{pub.get('connects', 0)}")
            if not opc["client"].get("security_string"):
                add(sec, "Security", "warn", "No security string, so OPC UA traffic is unencrypted",
                    "Set opcua.client.security_string, e.g. Basic256Sha256,SignAndEncrypt,cert.der,key.pem")

    # ---------------------------------------------------------------- gateway
    sec = "Gateway"
    if running:
        started = ctl.started_at
        add(sec, "State", "ok", f"Running since {started:%H:%M:%S}" if started else "Starting")
        stats = ctl.stats()
        q, qmax = snap.get("queue", 0), snap.get("queue_max", 0)
        if qmax and q > qmax * 0.5:
            add(sec, "Queue", "problem" if q > qmax * 0.9 else "warn", f"{q:,} of {qmax:,} waiting",
                "OPC UA is falling behind or unreachable. Traps are dropped when the queue is full.")
        else:
            add(sec, "Queue", "ok", f"{q:,} of {qmax:,} waiting")
        if stats.get("dropped"):
            add(sec, "Dropped traps", "problem", f"{stats['dropped']:,}",
                "Traps were lost because the queue was full or publishing failed. See the Log tab.")
        else:
            add(sec, "Dropped traps", "ok", "0")
        add(sec, "Trap rate", "info", f"{ctl.trap_rate(60):,} in the last minute, {ctl.trap_rate(900):,} in 15 min")
        add(sec, "Last trap", "info", f"{ctl.last_trap_at:%H:%M:%S}" if ctl.last_trap_at else "None yet")
        bad = stats.get("rejected", 0) + stats.get("malformed", 0)
        add(sec, "Rejected or unreadable", "warn" if bad else "ok", f"{bad:,}",
            "See the Rejected tab for the reason of each one." if bad else "")
    else:
        add(sec, "State", "info", "Stopped")

    # ---------------------------------------------------------------- environment
    sec = "Environment"
    add(sec, "Python", "info", f"{platform.python_version()} ({sys.executable})")
    add(sec, "Operating system", "info", f"{platform.system()} {platform.release()} ({platform.machine()})")
    add(sec, "Computer name", "info", socket.gethostname())
    if tk_version:
        add(sec, "Tk", "info", tk_version)
    crypto = package_version("cryptography")
    add(sec, "cryptography", "ok" if crypto else "warn", f"version {crypto}" if crypto else "Not installed",
        "" if crypto else "SNMPv3 encryption (DES/AES) needs it: pip install cryptography")
    add(sec, "PyYAML", "info", f"version {package_version('PyYAML') or 'unknown'}")
    admin = is_admin()
    if admin is not None:
        add(sec, "Administrator rights", "info", "Yes" if admin else "No")
    add(sec, "Working folder", "info", str(Path.cwd()))
    return out


def summarize(checks: list[Check]) -> str:
    p = sum(c.status == "problem" for c in checks)
    w = sum(c.status == "warn" for c in checks)
    if not p and not w:
        return "No problems found"
    parts = []
    if p:
        parts.append(f"{p} problem{'s' if p != 1 else ''}")
    if w:
        parts.append(f"{w} warning{'s' if w != 1 else ''}")
    return ", ".join(parts)


def report_text(checks: list[Check], when: datetime | None = None) -> str:
    """Plain-text report for copying into an email or ticket. No secrets are included."""
    when = when or datetime.now()
    lines = [f"snmp2opcua diagnostics, {when:%Y-%m-%d %H:%M:%S}", f"Summary: {summarize(checks)}", ""]
    section = None
    for c in checks:
        if c.section != section:
            section = c.section
            lines += ["", f"[{section}]"]
        lines.append(f"  {c.label:<8} {c.name}: {c.result}")
        if c.hint and c.status in ("problem", "warn"):
            lines.append(f"           Fix: {c.hint}")
    return "\n".join(lines).replace("\n\n\n", "\n\n").strip() + "\n"
