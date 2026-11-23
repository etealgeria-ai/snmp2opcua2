"""Recognise traps sent by the Kepware / KEPServerEX SNMP Agent Plug-In.

From the plug-in's help (SNMP Agent Plug-In, "System Objects Description"):
each agent exposes system objects under 1.3.6.1.4.1.30144.12.<agent>.1.<n>.0, where
<agent> is the agent's MIB sub-identifier:

    sysDescr .1  sysObjectID .2  sysUpTime .3  sysContact .4  sysName .5  sysLocation .6
    lastTrapDescr .7   (Kepware only; no RFC 1213 equivalent)

When the agent sends a trap, the trap's description is written to lastTrapDescr and that
object is included as a variable binding in the trap. We lift it into Trap.description,
give the system objects readable names, and record the agent sub-identifier.
"""
from __future__ import annotations

import re

from .trap import Trap

KEPWARE_ENTERPRISE = "1.3.6.1.4.1.30144"
KEPWARE_SNMP_AGENT = "1.3.6.1.4.1.30144.12"
VENDOR = "Kepware SNMP Agent"

SYSTEM_OBJECTS = {
    1: "sysDescr",
    2: "sysObjectID",
    3: "sysUpTime",
    4: "sysContact",
    5: "sysName",
    6: "sysLocation",
    7: "lastTrapDescr",
}

_LOCAL_SYSTEM_OBJECT = re.compile(r"^1\.3\.6\.1\.4\.1\.30144\.12\.(\d+)\.1\.([1-7])\.0$")
_AGENT_SUBTREE = re.compile(r"^1\.3\.6\.1\.4\.1\.30144\.12\.(\d+)(\.|$)")


def system_object(oid: str) -> tuple[int, str] | None:
    """(agent sub-identifier, object name) for a Kepware local system-object OID."""
    m = _LOCAL_SYSTEM_OBJECT.match(oid)
    if not m:
        return None
    return int(m.group(1)), SYSTEM_OBJECTS[int(m.group(2))]


def agent_of(oid: str | None) -> int | None:
    m = _AGENT_SUBTREE.match(oid or "")
    return int(m.group(1)) if m else None


def annotate(trap: Trap) -> bool:
    """Enrich a trap in place if it comes from a Kepware SNMP Agent. Returns True if it did."""
    agent = agent_of(trap.trap_oid) or agent_of(trap.enterprise)
    found = agent is not None
    for vb in trap.varbinds:
        hit = system_object(vb.oid)
        if hit is None:
            continue
        found = True
        agent_id, name = hit
        agent = agent if agent is not None else agent_id
        vb.name = name
        if name == "lastTrapDescr" and vb.value not in (None, ""):
            trap.description = str(vb.value)
    if found:
        trap.vendor = VENDOR
        trap.agent_id = agent
    return found
