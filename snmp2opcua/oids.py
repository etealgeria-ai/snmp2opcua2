"""Human-readable names for common OIDs (no MIB compiler required).

Add your own vendor OIDs in config.yaml under ``traps.oid_names``.
"""
from __future__ import annotations

SYS_UPTIME_0 = "1.3.6.1.2.1.1.3.0"
SNMP_TRAP_OID_0 = "1.3.6.1.6.3.1.1.4.1.0"
COLD_START = "1.3.6.1.6.3.1.1.5.1"
WARM_START = "1.3.6.1.6.3.1.1.5.2"
LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
LINK_UP = "1.3.6.1.6.3.1.1.5.4"
AUTHENTICATION_FAILURE = "1.3.6.1.6.3.1.1.5.5"
EGP_NEIGHBOR_LOSS = "1.3.6.1.6.3.1.1.5.6"

# RFC 1215 generic traps (v1) map to these
GENERIC_TRAP_OIDS = {
    0: COLD_START,
    1: WARM_START,
    2: LINK_DOWN,
    3: LINK_UP,
    4: AUTHENTICATION_FAILURE,
    5: EGP_NEIGHBOR_LOSS,
}

# A small built-in set of common names. Prefix match is used.
BUILTIN = {
    SYS_UPTIME_0: "sysUpTime",
    SNMP_TRAP_OID_0: "snmpTrapOID",
    COLD_START: "coldStart",
    WARM_START: "warmStart",
    LINK_DOWN: "linkDown",
    LINK_UP: "linkUp",
    AUTHENTICATION_FAILURE: "authenticationFailure",
    EGP_NEIGHBOR_LOSS: "egpNeighborLoss",
    # IF-MIB
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    # UPS-MIB (RFC 1628) a few common traps
    "1.3.6.1.2.1.33.2.0.1": "upsTrapOnBattery",
    "1.3.6.1.2.1.33.2.0.2": "upsTrapTestCompleted",
    "1.3.6.1.2.1.33.2.0.3": "upsTrapAlarmEntryAdded",
    "1.3.6.1.2.1.33.2.0.4": "upsTrapAlarmEntryRemoved",
}


class OidResolver:
    def __init__(self, extra: dict | None = None):
        self.names = dict(BUILTIN)
        if extra:
            self.names.update(extra)

    def name(self, oid: str) -> str:
        if oid in self.names:
            return self.names[oid]
        # longest prefix match
        best = None
        for prefix, name in self.names.items():
            if oid.startswith(prefix + ".") and (best is None or len(prefix) > len(best[0])):
                best = (prefix, name)
        if best:
            return f"{best[1]}.{oid[len(best[0])+1:]}"
        return oid
