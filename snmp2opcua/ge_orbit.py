"""GE MDS Orbit: read the remote radios' RSSI, IP and link state from the master station.

The master station (e.g. an Orbit LN4 module in an MCR) lists its connected remotes in
MDS-IF-LN-MIB::mIfLnStatusConnRemTable. Its entry is 1.3.6.1.4.1.4130.10.2.5.1.2.2.1
(mdsInterfaces = 1.3.6.1.4.1.4130.10.2, mdsIfLnMIB = mdsInterfaces.5) and the columns read
here are:

    .2  mIfLnStatusConnRemIpAddress   InetIpAddress: OCTET STRING of 4 (IPv4) or 16 (IPv6) octets
    .4  mIfLnStatusConnRemLinkStatus  LinkStatus: initializing(0) .. associated(4), disassociated(5)
    .6  mIfLnStatusConnRemRssi        Integer32, received signal strength in dBm

The row index is INDEX { ifIndex, mIfLnStatusConnRemAddress }. MacAddress is a fixed-size
string (SIZE (6)), so it's encoded as 6 sub-identifiers with no length in front:
<ifIndex>.<6 MAC octets>. Rows age out (mIfLnStatusConnRemTimeToLive), so a remote can
still be listed after its link has dropped; the link status tells the two apart.

The RSSI and IP columns and the index parsing are the same as the pysnmp script this module
was built from; only the transport is the gateway's own SNMP code. Run it on its own to
print the same report:

    python -m snmp2opcua.ge_orbit --ip 192.168.1.10 --community public
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys
from dataclasses import dataclass

from .snmp_client import SnmpClient, SnmpErrorStatus, SnmpTimeout
from .trap import VarBind

BASE_TABLE = "1.3.6.1.4.1.4130.10.2.5.1.2.2.1"     # mIfLnStatusConnRemEntry
IP_COL = f"{BASE_TABLE}.2"                         # mIfLnStatusConnRemIpAddress
LINK_COL = f"{BASE_TABLE}.4"                       # mIfLnStatusConnRemLinkStatus
RSSI_COL = f"{BASE_TABLE}.6"                       # mIfLnStatusConnRemRssi

# MDS-IF-LN-MIB LinkStatus
LINK_STATUS = {0: "initializing", 1: "scanning", 2: "negotiating", 3: "authenticating", 4: "associated",
               5: "disassociated"}
ASSOCIATED = 4


@dataclass
class Remote:
    mac: str              # "00:06:3D:12:34:56"
    if_index: int
    ip: str
    rssi: int | None      # dBm
    link_status: int | None = None   # LinkStatus; None when the master doesn't report it

    @property
    def key(self) -> str:
        """MAC without separators: a valid tag/folder name (e.g. 00063D123456)."""
        return self.mac.replace(":", "")

    @property
    def link_text(self) -> str:
        if self.link_status is None:
            return ""
        return LINK_STATUS.get(self.link_status, f"unknown({self.link_status})")

    @property
    def associated(self) -> bool | None:
        """True when the link is up; None when the link status wasn't read."""
        return None if self.link_status is None else self.link_status == ASSOCIATED


def split_index(suffix: str) -> tuple[int, str] | None:
    """'3.0.6.61.18.52.86' -> (3, '00:06:3D:12:34:56'); None if it isn't ifIndex + 6 octets.

    MacAddress has a fixed size, so the MIB's index has no length octet. An agent that sends
    one anyway ('3.6.0.6.61.18.52.86') is accepted too; anything else is not this table's row.
    """
    parts = suffix.split(".")
    if len(parts) == 8 and parts[1] == "6":
        parts = parts[:1] + parts[2:]          # length-prefixed MAC
    if len(parts) != 7:
        return None
    try:
        octets = [int(p) for p in parts[1:7]]
        if any(not 0 <= o <= 255 for o in octets):
            return None
        return int(parts[0]), ":".join(f"{o:02X}" for o in octets)
    except ValueError:
        return None


def ip_text(vb: VarBind | None) -> str:
    """InetIpAddress (4 or 16 raw octets), an IpAddress, or an address sent as text."""
    if vb is None or vb.value is None:
        return "N/A"
    if vb.type == "Octet String":
        raw = bytes(vb.raw)
        if len(raw) == 4:
            return str(ipaddress.IPv4Address(raw))
        if len(raw) == 16:
            v6 = ipaddress.IPv6Address(raw)
            return str(v6.ipv4_mapped or v6)                 # ::ffff:10.0.0.5 -> 10.0.0.5
    return str(vb.value)


def link_value(vb: VarBind | None) -> int | None:
    if vb is None or isinstance(vb.value, bool) or not isinstance(vb.value, int):
        return None
    return vb.value


def rssi_value(vb: VarBind) -> int | None:
    if isinstance(vb.value, (int, float)) and not isinstance(vb.value, bool):
        return int(vb.value)
    try:
        return int(str(vb.value).replace("dBm", "").strip())
    except (TypeError, ValueError):
        return None


def by_suffix(rows: list[VarBind], column: str) -> dict[str, VarBind]:
    prefix = column + "."
    return {vb.oid[len(prefix):]: vb for vb in rows if vb.oid.startswith(prefix)}


async def read_remotes(client: SnmpClient, max_repetitions: int = 20) -> list[Remote]:
    """Walk the RSSI, IP and link status columns and join them by row index.

    The link status is extra to the original script. If the master doesn't answer for that
    column (older firmware), remotes are read without it and count as linked while listed.
    """
    rssi_rows = by_suffix(await client.walk(RSSI_COL, max_repetitions), RSSI_COL)
    ip_rows = by_suffix(await client.walk(IP_COL, max_repetitions), IP_COL)
    try:
        link_rows = by_suffix(await client.walk(LINK_COL, max_repetitions), LINK_COL)
    except SnmpErrorStatus:
        link_rows = {}
    remotes = []
    for suffix, vb in rssi_rows.items():
        idx = split_index(suffix)
        if idx is None:
            continue
        if_index, mac = idx
        remotes.append(Remote(mac, if_index, ip_text(ip_rows.get(suffix)), rssi_value(vb),
                              link_value(link_rows.get(suffix))))
    return remotes


def format_report(remotes: list[Remote]) -> str:
    lines = [f"{'REMOTE_MAC':<18} {'REMOTE_IP':<16} {'RSSI (dBm)':<12} {'IF_INDEX'}", "-" * 58]
    for r in remotes:
        rssi = "N/A" if r.rssi is None else str(r.rssi)
        lines.append(f"{r.mac:<18} {r.ip:<16} {rssi:<12} {r.if_index}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="snmp2opcua.ge_orbit",
                                 description="Print RSSI and IP of the remotes connected to a GE MDS Orbit master")
    ap.add_argument("--ip", default="192.168.1.10", help="master station address (default 192.168.1.10)")
    ap.add_argument("--community", default="public")
    ap.add_argument("--version", choices=["1", "2c"], default="2c")
    ap.add_argument("--port", type=int, default=161)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--retries", type=int, default=1)
    args = ap.parse_args(argv)

    async def run() -> list[Remote]:
        client = SnmpClient(args.ip, args.community, args.version, args.port, args.timeout, args.retries)
        try:
            return await read_remotes(client)
        finally:
            client.close()
    try:
        remotes = asyncio.run(run())
    except (SnmpTimeout, SnmpErrorStatus, OSError) as exc:
        print(f"Couldn't read {args.ip}: {exc}", file=sys.stderr)
        return 1
    print(format_report(remotes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
