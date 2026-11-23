"""A small SNMP v1/v2c agent for tests: serves a dict of OIDs with GET/GETNEXT/GETBULK."""
import asyncio

from snmp2opcua import ber

ORBIT_TABLE = "1.3.6.1.4.1.4130.10.2.5.1.2.2.1"


def oid_key(oid: str):
    return tuple(int(x) for x in oid.split("."))


def orbit_mib(remotes, if_index=3, ip_as_octets=True, link=True, length_prefixed=False):
    """The GE MDS Orbit master's MDS-IF-LN-MIB::mIfLnStatusConnRemTable.

    remotes: (mac 'AA:BB:..', ip, rssi) or (mac, ip, rssi, link status). Column types follow
    the MIB: the IP is an InetIpAddress (OCTET STRING of 4 or 16 octets) unless ip_as_octets
    is False (IpAddress, as some firmware sends); link=False leaves out the link status
    column (older firmware); length_prefixed puts a length before the MAC in the index, as a
    non-conforming agent might.
    """
    import ipaddress
    mib = {"1.3.6.1.2.1.1.5.0": ber.encode_octets("LN4-MASTER"),
           "1.3.6.1.2.1.1.3.0": ber.encode_int(123456, ber.TIMETICKS)}
    for remote in remotes:
        mac, ip, rssi = remote[:3]
        status = remote[3] if len(remote) > 3 else 4                  # associated(4)
        octets = bytes(int(b, 16) for b in mac.split(":"))
        idx = f"{if_index}." + ("6." if length_prefixed else "") + ".".join(str(b) for b in octets)
        mib[f"{ORBIT_TABLE}.1.{idx}"] = ber.encode_octets(octets)                  # ConnRemAddress
        if ip_as_octets:
            mib[f"{ORBIT_TABLE}.2.{idx}"] = ber.encode_octets(ipaddress.ip_address(ip).packed)
        else:
            mib[f"{ORBIT_TABLE}.2.{idx}"] = ber.encode_ip(ip)
        mib[f"{ORBIT_TABLE}.3.{idx}"] = ber.encode_int(300, ber.GAUGE32)          # TimeToLive
        if link:
            mib[f"{ORBIT_TABLE}.4.{idx}"] = ber.encode_int(status)                 # LinkStatus
        mib[f"{ORBIT_TABLE}.5.{idx}"] = ber.encode_int(1, ber.GAUGE32)            # NicId
        mib[f"{ORBIT_TABLE}.6.{idx}"] = ber.encode_int(rssi)                       # Rssi
        mib[f"{ORBIT_TABLE}.7.{idx}"] = ber.encode_int(25, ber.GAUGE32)           # Evm
    mib["1.3.6.1.4.1.4130.99.1.0"] = ber.encode_int(7)               # something after the table
    return mib


class FakeAgent(asyncio.DatagramProtocol):
    def __init__(self, mib, community="public", max_bulk=None, drop=0):
        self.mib = dict(mib)
        self.community = community.encode()
        self.max_bulk = max_bulk          # reply tooBig when max-repetitions exceeds this
        self.drop = drop                  # ignore this many requests (timeouts)
        self.requests = []
        self.transport = None

    @property
    def keys(self):
        return sorted(self.mib, key=oid_key)

    def connection_made(self, transport):
        self.transport = transport

    def _next(self, oid):
        k = oid_key(oid)
        return next((o for o in self.keys if oid_key(o) > k), None)

    def datagram_received(self, data, addr):
        ms, me = ber.expect(data, 0, ber.SEQUENCE)
        vs, ve = ber.expect(data, ms, ber.INTEGER, me)
        version = ber.decode_int(data[vs:ve])
        cs, ce = ber.expect(data, ve, ber.OCTET_STRING, me)
        if data[cs:ce] != self.community:
            return                                    # agents ignore unknown communities
        tag, ps, pe = ber.read_tlv(data, ce, me)
        rs, re_ = ber.expect(data, ps, ber.INTEGER, pe)
        req_id = ber.decode_int(data[rs:re_])
        a_s, a_e = ber.expect(data, re_, ber.INTEGER, pe)
        b_s, b_e = ber.expect(data, a_e, ber.INTEGER, pe)
        b = ber.decode_int(data[b_s:b_e])            # GETBULK max-repetitions
        ls, le = ber.expect(data, b_e, ber.SEQUENCE, pe)
        oids, pos = [], ls
        while pos < le:
            s, e = ber.expect(data, pos, ber.SEQUENCE, le)
            os_, oe = ber.expect(data, s, ber.OBJECT_IDENTIFIER, e)
            oids.append(ber.decode_oid(data[os_:oe]))
            pos = e
        self.requests.append((tag, oids, b))
        if self.drop > 0:
            self.drop -= 1
            return
        status, index, out = 0, 0, []
        if tag == 0xA0:                                # GET
            for i, o in enumerate(oids, 1):
                if o in self.mib:
                    out.append((o, self.mib[o]))
                elif version == 0:
                    status, index = 2, i               # noSuchName
                    out = [(x, ber.encode_null()) for x in oids]
                    break
                else:
                    out.append((o, b"\x80\x00"))       # noSuchObject
        elif tag == 0xA1:                              # GETNEXT
            for i, o in enumerate(oids, 1):
                n = self._next(o)
                if n is None:
                    if version == 0:
                        status, index = 2, i
                        out = [(x, ber.encode_null()) for x in oids]
                        break
                    out.append((o, b"\x82\x00"))       # endOfMibView
                else:
                    out.append((n, self.mib[n]))
        elif tag == 0xA5:                              # GETBULK (non-repeaters a, max-repetitions b)
            if self.max_bulk is not None and b > self.max_bulk:
                status = 1                             # tooBig
                out = [(x, ber.encode_null()) for x in oids]
            else:
                for o in oids:
                    cur = o
                    for _ in range(b):
                        n = self._next(cur)
                        if n is None:
                            out.append((cur, b"\x82\x00"))
                            break
                        out.append((n, self.mib[n]))
                        cur = n
        vbs = b"".join(ber.sequence(ber.encode_oid(o), v) for o, v in out)
        pdu = ber.tlv(0xA2, ber.encode_int(req_id) + ber.encode_int(status) + ber.encode_int(index)
                      + ber.tlv(ber.SEQUENCE, vbs))
        self.transport.sendto(ber.sequence(ber.encode_int(version), ber.encode_octets(self.community), pdu), addr)


async def start_agent(mib, **kw):
    loop = asyncio.get_running_loop()
    agent = FakeAgent(mib, **kw)
    transport, _ = await loop.create_datagram_endpoint(lambda: agent, local_addr=("127.0.0.1", 0))
    return agent, transport, transport.get_extra_info("sockname")[1]
