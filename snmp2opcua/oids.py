"""Human-readable names for common OIDs (no MIB compiler required).

Add your own vendor OIDs in config.yaml under ``traps.oid_names``.
"""
from __future__ import annotations

SYS_UPTIME_0 = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID_0 = "1.3.6.1.6.3.1.1.4.1.0"
SNMP_TRAP_ENTERPRISE_0 = "1.3.6.1.6.3.1.1.4.3.0"
SNMP_TRAPS = "1.3.6.1.6.3.1.1.5"  # generic traps: coldStart = .1 ... egpNeighborLoss = .6

BUILTIN_NAMES: dict[str, str] = {
    # SNMPv2-MIB
    "1.3.6.1.2.1.1.1": "sysDescr",
    "1.3.6.1.2.1.1.2": "sysObjectID",
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.2.1.1.4": "sysContact",
    "1.3.6.1.2.1.1.5": "sysName",
    "1.3.6.1.2.1.1.6": "sysLocation",
    "1.3.6.1.6.3.1.1.4.1": "snmpTrapOID",
    "1.3.6.1.6.3.1.1.4.3": "snmpTrapEnterprise",
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
    # SNMP-COMMUNITY-MIB
    "1.3.6.1.6.3.18.1.3": "snmpTrapAddress",
    "1.3.6.1.6.3.18.1.4": "snmpTrapCommunity",
    # IF-MIB
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.3": "ifType",
    "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.31.1.1.1.1": "ifName",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
    # ENTITY / UPS / misc frequently seen in OT networks
    "1.3.6.1.2.1.47.2.0.1": "entConfigChange",
    "1.3.6.1.2.1.33.2.0.1": "upsTrapOnBattery",
    "1.3.6.1.2.1.33.2.0.2": "upsTrapTestCompleted",
    "1.3.6.1.2.1.33.2.0.3": "upsTrapAlarmEntryAdded",
    "1.3.6.1.2.1.33.2.0.4": "upsTrapAlarmEntryRemoved",
    "1.3.6.1.2.1.17.0.1": "newRoot",
    "1.3.6.1.2.1.17.0.2": "topologyChange",
    # Kepware / PTC (KEPServerEX SNMP Agent Plug-In); system objects are named in kepware.py
    "1.3.6.1.4.1.30144": "kepware",
    "1.3.6.1.4.1.30144.12": "kepwareSnmpAgent",
}


class OidResolver:
    """Longest-prefix OID -> name lookup. ``1.3.6.1.2.1.2.2.1.8.3`` -> ``ifOperStatus.3``."""

    def __init__(self, extra: dict[str, str] | None = None):
        self._names = dict(BUILTIN_NAMES)
        for oid, name in (extra or {}).items():
            self._names[str(oid).strip(".")] = str(name)

    def name(self, oid: str) -> str:
        if oid in self._names:
            return self._names[oid]
        parts = oid.split(".")
        for cut in range(len(parts) - 1, 1, -1):
            prefix = ".".join(parts[:cut])
            if prefix in self._names:
                return self._names[prefix] + "." + ".".join(parts[cut:])
        return oid
