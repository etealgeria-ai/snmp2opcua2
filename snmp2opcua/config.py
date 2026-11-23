"""Load config.yaml and merge it over sensible defaults."""
from __future__ import annotations

import copy
import ipaddress
import os
import re
from pathlib import Path

import yaml

DEFAULTS: dict = {
    "snmp": {
        "listen_host": "0.0.0.0",
        "listen_port": 162,
        "communities": ["public"],     # empty list = accept any community
        "allowed_sources": [],         # IPs / CIDRs; empty = accept from anywhere
        "respond_to_informs": True,
        "versions": ["v1", "v2c", "v3"],   # which SNMP versions to accept
        "network_interfaces": [],          # [{address, port}]; empty = listen_host:listen_port
        "accept_all_hosts": None,          # None = accept all when allowed_sources is empty
        "v3": {
            "engine_id": None,             # hex; auto-generated and stored in state_file if empty
            "state_file": "snmp2opcua_engine.json",
            "replay_protection": True,
            "users": [],
        },
    },
    "opcua": {
        "mode": "server",              # "server" or "client"
        "server": {
            "endpoint": "opc.tcp://0.0.0.0:4840/snmp2opcua/",
            "server_name": "SNMP Trap Gateway",
            "namespace": "urn:snmp2opcua:gateway",
            "security_policies": ["NoSecurity"],
            "certificate": None,
            "private_key": None,
            "events": True,
            "recent_traps": 50,
            "max_devices": 1000,
        },
        "client": {
            "url": "opc.tcp://localhost:4840",
            "username": None,
            "password": None,
            "security_string": None,
            "timeout": 4,
            "reconnect_delay": 5,
            "nodes": {},
        },
    },
    "traps": {
        "queue_size": 10000,
        "oid_names": {},
        "severity": {"default": 500, "rules": {}},
    },
    "channels": [],                        # SNMP-driver style Channel -> Device -> trap tags
    "polling_state_file": "snmp2opcua_slots.json",   # remembers which radio is Remote1, Remote2, ...
    "logging": {"level": "INFO"},
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict) and key != "nodes":
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env(value):
    """Replace ${VAR} with the environment variable VAR (for keys you don't want in the file)."""
    if not isinstance(value, str):
        return value

    def sub(m):
        if m.group(1) not in os.environ:
            raise ValueError(f"environment variable {m.group(1)} is not set")
        return os.environ[m.group(1)]
    return _ENV.sub(sub, value)


def build_v3_users(cfg: dict) -> list:
    from .usm import UsmUser
    users = []
    seen = set()
    for i, u in enumerate(cfg["snmp"]["v3"].get("users") or []):
        if not isinstance(u, dict):
            raise ValueError(f"snmp.v3.users[{i}] must be a mapping")
        name = str(u.get("name") or "")
        if name in seen:
            raise ValueError(f"duplicate SNMPv3 user {name!r}")
        seen.add(name)
        users.append(UsmUser.create(
            name, u.get("auth_protocol"), expand_env(u.get("auth_key")),
            u.get("priv_protocol"), expand_env(u.get("priv_key")), u.get("engine_ids")))
    return users


def _valid_ip(text: str, allow_network: bool = False) -> str:
    try:
        if allow_network and "/" in str(text):
            return str(ipaddress.ip_network(str(text), strict=False))
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        raise ValueError(f"Invalid IP address {text!r}. Enter a valid IPv4 address in quad-dotted notation, "
                         f"such as 127.0.0.1.") from None


def validate_snmp(snmp: dict) -> None:
    """Checks modelled on the SNMP agent/driver configuration messages."""
    seen_comm: set[str] = set()
    for c in snmp.get("communities") or []:
        if str(c) in seen_comm:
            raise ValueError(f"The community {c} has already been added.")
        seen_comm.add(str(c))
    seen_hosts: set[str] = set()
    for h in snmp.get("allowed_sources") or []:
        norm = _valid_ip(h, allow_network=True)
        if norm in seen_hosts:
            raise ValueError(f"The host IP {h} has already been added.")
        seen_hosts.add(norm)
    seen_if: set[tuple] = set()
    for ni in snmp.get("network_interfaces") or []:
        if not isinstance(ni, dict) or "port" not in ni:
            raise ValueError("Each network interface needs an address and a port, e.g. {address: 0.0.0.0, port: 162}")
        addr = _valid_ip(ni.get("address", "0.0.0.0"))
        port = int(ni["port"])
        if not 0 < port < 65536:
            raise ValueError(f"Network interface {addr}: port must be within the range of 1 to 65535")
        if (addr, port) in seen_if:
            raise ValueError(f"The network interface {addr}; Port: {port} has already been added.")
        seen_if.add((addr, port))


def listen_endpoints(cfg: dict) -> list[tuple[str, int, str]]:
    """(address, port, protocol) to listen on: network interfaces plus each enabled device's trap port."""
    snmp = cfg["snmp"]
    eps: list[tuple[str, int, str]] = []
    for ni in snmp.get("network_interfaces") or [{"address": snmp["listen_host"], "port": snmp["listen_port"]}]:
        eps.append((str(ni.get("address", "0.0.0.0")), int(ni["port"]), "UDP"))
    for dev in cfg.get("_devices") or []:
        if dev.trap_enabled:
            eps.append((snmp["listen_host"], dev.port, dev.protocol))
    out: list[tuple[str, int, str]] = []
    for host, port, proto in eps:
        wildcard = any(p == port and pr == proto and h in ("0.0.0.0", "::") for h, p, pr in out)
        if (host, port, proto) not in out and not wildcard:
            if host in ("0.0.0.0", "::"):      # a wildcard listener replaces specific ones on that port
                out = [e for e in out if not (e[1] == port and e[2] == proto)]
            out.append((host, port, proto))
    return out


def load_config(path: str | Path | None) -> dict:
    data: dict = {}
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    cfg = _merge(DEFAULTS, data)
    mode = cfg["opcua"]["mode"]
    if mode not in ("server", "client"):
        raise ValueError(f"opcua.mode must be 'server' or 'client', got {mode!r}")
    port = int(cfg["snmp"]["listen_port"])
    if not 0 < port < 65536:
        raise ValueError(f"snmp.listen_port out of range: {port}")
    bad = set(cfg["snmp"]["versions"] or []) - {"v1", "v2c", "v3"}
    if bad:
        raise ValueError(f"snmp.versions has unknown entries {sorted(bad)}; use v1, v2c, v3")
    validate_snmp(cfg["snmp"])
    users = build_v3_users(cfg)   # validates keys/protocols at startup

    from .snmp_driver import DriverConfigError, build_devices
    from .tag_csv import csv_loader
    base_dir = Path(path).resolve().parent if path else Path.cwd()
    try:
        devices = build_devices(cfg.get("channels") or [], base_dir, csv_loader,
                                default_port=int(cfg["snmp"]["listen_port"]))
    except DriverConfigError as exc:
        raise ValueError(str(exc)) from None
    for dev in devices:
        if dev.channel == "Gateway":
            raise ValueError("The channel name 'Gateway' is reserved for the gateway's own OPC UA objects")
        want = {"1": "v1", "2c": "v2c", "3": "v3"}[dev.snmp_version]
        if dev.trap_enabled and want not in cfg["snmp"]["versions"]:
            raise ValueError(f"Device {dev.path} uses SNMP version {dev.snmp_version}, but snmp.versions doesn't "
                             f"include {want}")
        u = dev.v3_user
        if u is not None:               # device v3 users authenticate traps like configured users
            same = next((x for x in users if x.name == u.name), None)
            if same is None:
                users.append(u)
            elif (same.auth, same.priv, same.auth_ku, same.priv_ku) != (u.auth, u.priv, u.auth_ku, u.priv_ku):
                raise ValueError(f"SNMPv3 user {u.name} is defined twice with different settings "
                                 f"(snmp.v3.users and device {dev.path})")
    cfg["snmp"]["v3"]["_users"] = users
    cfg["_devices"] = devices
    psf = cfg.get("polling_state_file")
    if psf and not Path(psf).is_absolute():              # next to the config file
        cfg["polling_state_file"] = str(base_dir / psf)
    cfg["_endpoints"] = listen_endpoints(cfg)
    return cfg
