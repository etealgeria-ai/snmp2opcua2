"""GE master stations as edited by the window's Stations page.

A station is a device under ``channels:`` whose ``polling.ge_orbit_remotes`` is true. This
module lists them, checks a filled-in form, and turns a save into the smallest possible
edit of config.yaml (via yaml_edit), so hand-written comments and layout survive.
No Tk here, so it is unit-tested directly.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import yaml

from .snmp_driver import MAX_RATE_MS, MIN_RATE_MS, DriverConfigError, _check_name
from .yaml_edit import append_to, delete_in, remove_from, set_in

DEFAULT_CHANNEL = "Radios"
DEFAULT_RSSI_WARNING = -95


@dataclass
class Station:
    channel: str
    name: str
    ip: str
    community: str = "public"
    version: str = "2c"
    port: int = 161
    scan_rate_ms: int = 10000
    timeout_ms: int = 2000
    retries: int = 1
    max_repetitions: int = 20
    rssi_warning_dbm: int | None = None
    receive_traps: bool = True
    auto_create_tags: bool = True
    remote_tags: int = 255
    remote_tag_prefix: str = "Remote"
    # where it lives in config.yaml (None for a new station)
    ci: int | None = None
    di: int | None = None
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def path(self) -> str:
        return f"{self.channel}.{self.name}"


def list_stations(text: str) -> list[Station]:
    data = yaml.safe_load(text) or {}
    out = []
    for ci, ch in enumerate(data.get("channels") or []):
        for di, d in enumerate((ch or {}).get("devices") or []):
            p = (d or {}).get("polling")
            if not isinstance(p, dict) or not p.get("ge_orbit_remotes"):
                continue
            dev_version = str(d.get("snmp_version", "2c")).lstrip("v")
            out.append(Station(
                channel=str(ch.get("name", "")), name=str(d.get("name", "")),
                ip=str(d.get("ip") or d.get("host") or ""),
                community=str(p.get("community", "public")),
                version=str(p.get("snmp_version", dev_version if dev_version in ("1", "2c") else "2c")).lstrip("v"),
                port=int(p.get("port", 161)), scan_rate_ms=int(p.get("scan_rate_ms", 10000)),
                timeout_ms=int(p.get("timeout_ms", 2000)), retries=int(p.get("retries", 1)),
                max_repetitions=int(p.get("max_repetitions", 20)),
                rssi_warning_dbm=None if p.get("rssi_warning_dbm") is None else int(p["rssi_warning_dbm"]),
                receive_traps=bool((d.get("trap") or {}).get("enabled", True)),
                auto_create_tags=bool(d.get("auto_create_tags", True)),
                remote_tags=int(p.get("remote_tags", 255)), remote_tag_prefix=str(p.get("remote_tag_prefix", "Remote")),
                ci=ci, di=di, raw=dict(d)))
    return out


def channel_names(text: str) -> list[str]:
    data = yaml.safe_load(text) or {}
    return [str(c.get("name")) for c in data.get("channels") or [] if isinstance(c, dict)]


def new_station(text: str) -> Station:
    """Defaults for the Add button: next free name in the first radio channel."""
    names = {s.path for s in list_stations(text)}
    data = yaml.safe_load(text) or {}
    taken = {f"{c.get('name')}.{d.get('name')}" for c in data.get("channels") or [] for d in c.get("devices") or []}
    n = 1
    while f"{DEFAULT_CHANNEL}.Master_{n}" in taken | names:
        n += 1
    return Station(channel=DEFAULT_CHANNEL, name=f"Master_{n}", ip="", rssi_warning_dbm=DEFAULT_RSSI_WARNING,
                   receive_traps=False, auto_create_tags=False)


def _int(text: str, field_name: str, lo: int, hi: int, what: str, problems: list) -> int | None:
    try:
        v = int(str(text).strip())
    except ValueError:
        problems.append((field_name, f"{what} must be a whole number"))
        return None
    if not lo <= v <= hi:
        problems.append((field_name, f"{what} must be within the range of {lo} to {hi}"))
        return None
    return v


def parse_form(values: dict, original: Station | None, text: str) -> tuple[Station | None, list[tuple[str, str]]]:
    """Check the form. Returns (station, problems); problems are (field, message) with manual-style wording."""
    problems: list[tuple[str, str]] = []
    channel = str(values.get("channel", "")).strip()
    name = str(values.get("name", "")).strip()
    for fld, kind, val in (("channel", "channel", channel), ("name", "device", name)):
        try:
            _check_name(kind, val)
        except DriverConfigError as exc:
            problems.append((fld, str(exc)))
    if channel == "Gateway":
        problems.append(("channel", "The channel name 'Gateway' is reserved for the gateway's own OPC UA objects"))

    ip = str(values.get("ip", "")).strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        problems.append(("ip", "Invalid IP address. Enter a valid IPv4 address in quad-dotted notation, "
                               "such as 192.168.1.10."))
    community = str(values.get("community", ""))
    if not community:
        problems.append(("community", "Enter the read community the master station accepts"))
    elif len(community) > 256:
        problems.append(("community", "The community can be up to 256 characters"))
    version = str(values.get("version", "2c")).lstrip("v")
    if version not in ("1", "2c"):
        problems.append(("version", "Polling uses SNMP version 1 or 2c"))
    port = _int(values.get("port", ""), "port", 1, 65535, "Port", problems)
    scan_rate_ms = None
    try:
        scan_rate_ms = int(round(float(str(values.get("scan_rate_s", "")).strip()) * 1000))
        if not MIN_RATE_MS <= scan_rate_ms <= MAX_RATE_MS:
            problems.append(("scan_rate_s", "The rate must be within the range of 10 milliseconds and 49 days."))
            scan_rate_ms = None
    except ValueError:
        problems.append(("scan_rate_s", "Scan rate must be a number of seconds, e.g. 10 or 0.5"))
    timeout_ms = _int(values.get("timeout_ms", ""), "timeout_ms", 50, 60000, "Timeout", problems)
    retries = _int(values.get("retries", ""), "retries", 0, 10, "Retries", problems)
    max_reps = _int(values.get("max_repetitions", ""), "max_repetitions", 1, 200, "Max repetitions", problems)
    remote_tags = _int(values.get("remote_tags", "255"), "remote_tags", 0, 1000, "Number of RSSI tags", problems)
    prefix = str(values.get("remote_tag_prefix", "Remote")).strip()
    try:
        _check_name("tag", prefix)
    except DriverConfigError as exc:
        problems.append(("remote_tag_prefix", str(exc)))
    rssi = None
    if values.get("rssi_enabled"):
        rssi = _int(values.get("rssi_warning_dbm", ""), "rssi_warning_dbm", -200, 0, "RSSI warning", problems)

    data = yaml.safe_load(text) or {}
    for ci, ch in enumerate(data.get("channels") or []):
        if str(ch.get("name")) != channel:
            continue
        for di, d in enumerate(ch.get("devices") or []):
            same = original is not None and (original.ci, original.di) == (ci, di)
            if str(d.get("name")) == name and not same:
                problems.append(("name", f"The device {channel}.{name} has already been added"))
    if problems:
        return None, problems
    assert port is not None and scan_rate_ms is not None and timeout_ms is not None
    assert retries is not None and max_reps is not None and remote_tags is not None
    st = Station(channel, name, ip, community, version, port, scan_rate_ms, timeout_ms, retries, max_reps, rssi,
                 bool(values.get("receive_traps")), bool(values.get("auto_create_tags")), remote_tags, prefix,
                 original.ci if original else None, original.di if original else None,
                 dict(original.raw) if original else {})
    return st, []


def _polling(st: Station) -> dict:
    p = {"community": st.community, "port": st.port, "snmp_version": st.version, "scan_rate_ms": st.scan_rate_ms,
         "timeout_ms": st.timeout_ms, "retries": st.retries, "max_repetitions": st.max_repetitions,
         "ge_orbit_remotes": True}
    if st.rssi_warning_dbm is not None:
        p["rssi_warning_dbm"] = st.rssi_warning_dbm
    p["remote_tags"] = st.remote_tags
    p["remote_tag_prefix"] = st.remote_tag_prefix
    return p


def _device_dict(st: Station) -> dict:
    d = dict(st.raw)
    d.update({"name": st.name, "ip": st.ip})
    d.pop("host", None)
    if "snmp_version" not in d:
        d["snmp_version"] = st.version
    d["auto_create_tags"] = st.auto_create_tags
    trap = dict(d.get("trap") or {})
    trap["enabled"] = st.receive_traps
    d["trap"] = trap
    polling = dict(d.get("polling") or {})
    polling.update(_polling(st))
    if st.rssi_warning_dbm is None:
        polling.pop("rssi_warning_dbm", None)
    d["polling"] = polling
    return d


def save_station(text: str, st: Station, original: Station | None) -> str:
    """config.yaml text with the station added or updated (only changed values are rewritten)."""
    data = yaml.safe_load(text) or {}
    channels = data.get("channels") or []
    if original is not None and original.channel == st.channel and original.ci is not None:
        base = ["channels", original.ci, "devices", original.di]
        raw = original.raw
        rawp = raw.get("polling") or {}
        if raw.get("name") != st.name:
            text = set_in(text, base + ["name"], st.name)
        if "host" in raw and "ip" not in raw:
            text = set_in(text, base + ["host"], st.ip)
        elif raw.get("ip") != st.ip:
            text = set_in(text, base + ["ip"], st.ip)
        if bool(raw.get("auto_create_tags", True)) != st.auto_create_tags:
            text = set_in(text, base + ["auto_create_tags"], st.auto_create_tags)
        if bool((raw.get("trap") or {}).get("enabled", True)) != st.receive_traps:
            text = set_in(text, base + ["trap", "enabled"], st.receive_traps)
        dev_version = str(raw.get("snmp_version", "2c")).lstrip("v")
        effective = {"community": "public", "port": 161, "scan_rate_ms": 10000, "timeout_ms": 2000, "retries": 1,
                     "max_repetitions": 20, "ge_orbit_remotes": True, "remote_tags": 255,
                     "remote_tag_prefix": "Remote",
                     "snmp_version": dev_version if dev_version in ("1", "2c") else None}
        effective.update(rawp)
        for key, value in _polling(st).items():
            current = effective.get(key)
            if key == "snmp_version" and current is not None:
                current = str(current).lstrip("v")
            if current != value:                     # write only real changes, not restated defaults
                text = set_in(text, base + ["polling", key], value)
        if st.rssi_warning_dbm is None and "rssi_warning_dbm" in rawp:
            text = delete_in(text, base + ["polling", "rssi_warning_dbm"])
        return text

    device = _device_dict(st)
    if original is not None and original.ci is not None:       # moved to another channel
        text = remove_from(text, ["channels", original.ci, "devices"], original.di)  # type: ignore[arg-type]
        data = yaml.safe_load(text) or {}
        channels = data.get("channels") or []
    target = next((i for i, c in enumerate(channels) if str(c.get("name")) == st.channel), None)
    if target is None:
        return append_to(text, ["channels"], {"name": st.channel, "devices": [device]})
    return append_to(text, ["channels", target, "devices"], device)


def lock_numbers(text: str, st: Station, slots: dict[int, str]) -> str:
    """Pin the current Remote numbering (number -> MAC) for a station, so it never changes."""
    if st.ci is None or st.di is None:
        raise ValueError("Save the station first")
    pins = {int(k): v for k, v in sorted(slots.items())}
    return set_in(text, ["channels", st.ci, "devices", st.di, "polling", "remote_slots"], pins)


def delete_station(text: str, st: Station) -> str:
    if st.ci is None or st.di is None:
        return text
    return remove_from(text, ["channels", st.ci, "devices"], st.di)
