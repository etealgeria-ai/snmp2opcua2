"""Tests for decoding, INFORM acks, filtering and the end-to-end UDP path.

Run:  python -m unittest discover -s tests -v
(asyncua is not needed for these tests; the OPC UA side is replaced by a fake publisher.)
"""
import asyncio
import random
import socket
import unittest

from snmp2opcua import ber
from snmp2opcua.config import load_config
from snmp2opcua.gateway import Gateway
from snmp2opcua.oids import OidResolver
from snmp2opcua.sendtrap import build_v1, build_v2, encode_typed, varbind
from snmp2opcua.severity import SeverityMap
from snmp2opcua.trap import UnsupportedMessage, build_inform_response, parse_message

# Hand-encoded SNMPv1 trap (independent of our encoder):
# community "public", enterprise 1.3.6.1.4.1.8072, agent 10.0.0.1, generic 6, specific 17,
# timestamp 12345, varbind 1.3.6.1.4.1.8072.2.3.2.1 = INTEGER 42
V1_PACKET = bytes.fromhex(
    "30 3a 02 01 00 04 06 70 75 62 6c 69 63 a4 2d 06 07 2b 06 01 04 01 bf 08 40 04 0a 00 00 01"
    "02 01 06 02 01 11 43 02 30 39 30 12 30 10 06 0b 2b 06 01 04 01 bf 08 02 03 02 01 02 01 2a")


def pdu_tag(packet):
    _, ms, me = ber.read_tlv(packet, 0)
    _, ve = ber.expect(packet, ms, ber.INTEGER, me)
    _, ce = ber.expect(packet, ve, ber.OCTET_STRING, me)
    return ber.read_tlv(packet, ce, me)[0]
SRC = ("192.0.2.10", 50000)
R = OidResolver()


class DecodeTests(unittest.TestCase):
    def test_v1_handcrafted(self):
        t = parse_message(V1_PACKET, SRC, R)
        self.assertEqual(t.version, "v1")
        self.assertEqual(t.community, "public")
        self.assertEqual(t.enterprise, "1.3.6.1.4.1.8072")
        self.assertEqual(t.agent_address, "10.0.0.1")
        self.assertEqual((t.generic_trap, t.specific_trap, t.uptime), (6, 17, 12345))
        self.assertEqual(t.trap_oid, "1.3.6.1.4.1.8072.0.17")  # RFC 3584 mapping
        self.assertEqual(len(t.varbinds), 1)
        self.assertEqual((t.varbinds[0].oid, t.varbinds[0].value), ("1.3.6.1.4.1.8072.2.3.2.1", 42))

    def test_v1_encoder_matches_handcrafted(self):
        pkt = build_v1("public", "1.3.6.1.4.1.8072", "10.0.0.1", 6, 17, 12345,
                       [varbind("1.3.6.1.4.1.8072.2.3.2.1", encode_typed("i", "42"))])
        self.assertEqual(pkt, V1_PACKET)

    def test_v1_generic_trap_mapping(self):
        pkt = build_v1("public", "1.3.6.1.4.1.9", "10.0.0.2", 2, 0, 1, [])
        t = parse_message(pkt, SRC, R)
        self.assertEqual((t.trap_oid, t.trap_name), ("1.3.6.1.6.3.1.1.5.3", "linkDown"))

    def test_v2c_all_types(self):
        vbs = [varbind("1.3.6.1.2.1.2.2.1.1.3", encode_typed("i", "-5")),
               varbind("1.3.6.1.2.1.2.2.1.2.3", encode_typed("s", "eth3 ✓")),
               varbind("1.3.6.1.4.1.1.1", encode_typed("u", "4294967295")),
               varbind("1.3.6.1.4.1.1.2", encode_typed("c", "2147483648")),
               varbind("1.3.6.1.4.1.1.3", encode_typed("C", str(2**64 - 1))),
               varbind("1.3.6.1.4.1.1.4", encode_typed("t", "100")),
               varbind("1.3.6.1.4.1.1.5", encode_typed("a", "172.16.0.9")),
               varbind("1.3.6.1.4.1.1.6", encode_typed("o", "1.3.6.1.4.1.99999.1")),
               varbind("1.3.6.1.4.1.1.7", encode_typed("x", "00:1a:2b:3c:4d:5e")),
               varbind("1.3.6.1.4.1.1.8", encode_typed("n", ""))]
        t = parse_message(build_v2("public", "linkDown", 777, vbs), SRC, R)
        self.assertEqual((t.version, t.pdu, t.uptime, t.trap_name), ("v2c", "trap", 777, "linkDown"))
        got = [(v.name, v.type, v.value) for v in t.varbinds]
        self.assertEqual(got, [
            ("ifIndex.3", "Integer32", -5), ("ifDescr.3", "Octet String", "eth3 ✓"),
            ("1.3.6.1.4.1.1.1", "Gauge32", 4294967295), ("1.3.6.1.4.1.1.2", "Counter32", 2147483648),
            ("1.3.6.1.4.1.1.3", "Counter64", 2**64 - 1), ("1.3.6.1.4.1.1.4", "TimeTicks", 100),
            ("1.3.6.1.4.1.1.5", "IpAddress", "172.16.0.9"),
            ("1.3.6.1.4.1.1.6", "Object Identifier", "1.3.6.1.4.1.99999.1"),
            ("1.3.6.1.4.1.1.7", "Octet String", "00:1a:2b:3c:4d:5e"), ("1.3.6.1.4.1.1.8", "Null", None)])
        self.assertIn('"trap_name": "linkDown"', t.to_json())
        self.assertNotIn("public", t.to_json())  # community is not exposed by default

    def test_inform_response(self):
        pkt = build_v2("private", "1.3.6.1.4.1.9999.0.1", 5,
                       [varbind("1.3.6.1.4.1.9999.1", encode_typed("s", "Door open"))],
                       inform=True, request_id=123456)
        t = parse_message(pkt, SRC, R)
        self.assertEqual((t.pdu, t.request_id), ("inform", 123456))
        resp = build_inform_response(pkt)
        # Response-PDU must echo request-id, have error-status 0 and the same varbinds
        _, ms, me = ber.read_tlv(resp, 0)
        _, ve = ber.expect(resp, ms, ber.INTEGER, me)
        _, ce = ber.expect(resp, ve, ber.OCTET_STRING, me)
        tag, ps, pe = ber.read_tlv(resp, ce, me)
        self.assertEqual(tag, 0xA2)
        rs, re_ = ber.expect(resp, ps, ber.INTEGER, pe)
        self.assertEqual(ber.decode_int(resp[rs:re_]), 123456)
        es, ee = ber.expect(resp, re_, ber.INTEGER, pe)
        self.assertEqual(ber.decode_int(resp[es:ee]), 0)
        self.assertTrue(resp.endswith(pkt[-40:]))

    def test_oid_and_int_edges(self):
        for oid in ["0.0", "1.3", "2.999.3", "1.3.6.1.4.1.4294967295.0", "1.3.6.1.2.1.1.3.0"]:
            enc = ber.encode_oid(oid)
            self.assertEqual(ber.decode_oid(enc[2:]), oid)
        for n in [0, 1, 127, 128, 255, 256, -1, -128, -129, 2**31 - 1, -2**31]:
            enc = ber.encode_int(n)
            self.assertEqual(ber.decode_int(enc[2:]), n)
        self.assertEqual(ber.encode_int(-128), b"\x02\x01\x80")
        self.assertEqual(ber.encode_int(128), b"\x02\x02\x00\x80")

    def test_unsupported(self):
        v3ish = ber.sequence(ber.encode_int(3), ber.encode_octets("x"))
        with self.assertRaises(UnsupportedMessage):
            parse_message(v3ish, SRC, R)
        get = ber.sequence(ber.encode_int(1), ber.encode_octets("public"),
                           ber.tlv(0xA0, ber.encode_int(1) + ber.encode_int(0) + ber.encode_int(0) + ber.sequence()))
        with self.assertRaises(UnsupportedMessage):
            parse_message(get, SRC, R)

    def test_garbage_never_crashes(self):
        rng = random.Random(1234)
        good = build_v2("public", "linkUp", 1, [varbind("1.3.6.1.2.1.2.2.1.1.1", encode_typed("i", "1"))])
        samples = [good[:i] for i in range(len(good))]
        for _ in range(3000):
            b = bytearray(good)
            for _ in range(rng.randint(1, 4)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            samples.append(bytes(b))
        samples += [bytes(rng.randrange(256) for _ in range(rng.randint(0, 80))) for _ in range(2000)]
        for s in samples:
            try:
                parse_message(s, SRC, R)
            except (ber.BerError, UnsupportedMessage):
                pass


class MappingTests(unittest.TestCase):
    def test_resolver(self):
        r = OidResolver({"1.3.6.1.4.1.9999.0.1": "doorOpen", ".1.3.6.1.4.1.9999.1": "doorId"})
        self.assertEqual(r.name("1.3.6.1.2.1.2.2.1.8.12"), "ifOperStatus.12")
        self.assertEqual(r.name("1.3.6.1.4.1.9999.0.1"), "doorOpen")
        self.assertEqual(r.name("1.3.6.1.4.1.9999.1.4"), "doorId.4")
        self.assertEqual(r.name("1.3.6.1.4.1.12345.1"), "1.3.6.1.4.1.12345.1")

    def test_severity(self):
        sm = SeverityMap({"default": 300, "rules": {"linkDown": 800, "1.3.6.1.4.1.9": 600,
                                                     "1.3.6.1.4.1.9.9.41": 900, "x": 5000}})
        def mk(oid):
            return parse_message(build_v2("public", oid, 1, []), SRC, R)
        self.assertEqual(sm.for_trap(mk("linkDown")), 800)
        self.assertEqual(sm.for_trap(mk("1.3.6.1.4.1.9.9.41.2.0.1")), 900)
        self.assertEqual(sm.for_trap(mk("1.3.6.1.4.1.9.1.0.5")), 600)
        self.assertEqual(sm.for_trap(mk("1.3.6.1.4.1.99.0.1")), 300)
        self.assertEqual(sm.by_name["x"], 1000)


class FakePublisher:
    def __init__(self):
        self.traps = []
        self.started = self.stopped = False
        self.got = asyncio.Event()

    async def start(self):
        self.started = True

    async def publish(self, trap):
        self.traps.append(trap)
        self.got.set()

    async def update_status(self, stats):
        self.stats = stats

    async def stop(self):
        self.stopped = True


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def test_udp_path(self):
        port = free_udp_port()
        cfg = load_config(None)
        cfg["snmp"].update(listen_host="127.0.0.1", listen_port=port, communities=["public"])
        pub = FakePublisher()
        gw = Gateway(cfg, publisher=pub)
        task = asyncio.create_task(gw.run())
        await asyncio.sleep(0.2)
        loop = asyncio.get_running_loop()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("127.0.0.1", 0))
        try:
            # 1) accepted v2c trap
            sock.sendto(build_v2("public", "linkDown", 9,
                                   [varbind("ifIndex", encode_typed("i", "1"))]), ("127.0.0.1", port))
            await asyncio.wait_for(pub.got.wait(), 2)
            # 2) wrong community -> rejected
            sock.sendto(build_v2("wrong", "linkUp", 9, []), ("127.0.0.1", port))
            # 3) garbage -> malformed
            sock.sendto(b"\x30\x03\x02\x01", ("127.0.0.1", port))
            # 4) inform -> acknowledged and published
            sock.sendto(build_v2("public", "coldStart", 1, [], inform=True, request_id=42),
                                   ("127.0.0.1", port))
            reply = await asyncio.wait_for(loop.sock_recv(sock, 2048), 2)
            self.assertEqual(pdu_tag(reply), 0xA2)
            # 5) v1 trap
            sock.sendto(V1_PACKET, ("127.0.0.1", port))
            for _ in range(50):
                if len(pub.traps) >= 3:
                    break
                await asyncio.sleep(0.05)
        finally:
            sock.close()
            gw.stop()
            await asyncio.wait_for(task, 3)

        self.assertTrue(pub.started and pub.stopped)
        self.assertEqual([t.trap_name for t in pub.traps], ["linkDown", "coldStart", "1.3.6.1.4.1.8072.0.17"])
        self.assertEqual(pub.traps[0].source_ip, "127.0.0.1")
        s = gw.stats
        self.assertEqual((s.received, s.published, s.rejected, s.malformed, s.dropped), (3, 3, 1, 1, 0))


if __name__ == "__main__":
    unittest.main()
