"""SNMPv3 / USM tests.  Run:  python -m unittest discover -s tests -v"""
import asyncio
import hashlib
import os
import random
import socket
import tempfile
import unittest
from pathlib import Path

from snmp2opcua import ber
from snmp2opcua.config import build_v3_users, load_config
from snmp2opcua.gateway import Gateway
from snmp2opcua.oids import OidResolver
from snmp2opcua.sendtrap import build_v3, discovery_probe, encode_typed, read_v3_reply, send_v3_inform, varbind
from snmp2opcua.snmpv3 import PDU_REPORT, SnmpV3Engine, V3Rejected, load_engine_state
from snmp2opcua.trap import PDU_GET_RESPONSE, UnsupportedMessage
from snmp2opcua.usm import AUTH_PROTOCOLS, PRIV_PROTOCOLS, UsmError, UsmUser, localize_key, password_to_key

R = OidResolver()
SRC = ("198.51.100.7", 40000)
DEVICE_ENGINE = bytes.fromhex("800000090300aabbccddeeff")
GW_ENGINE = bytes.fromhex("80001f88050102030405060708")
VBS = [varbind("ifIndex.3", encode_typed("i", "3")), varbind("ifDescr.3", encode_typed("s", "Gi0/3"))]

_users = {}


def user(auth="SHA256", priv="AES", name="opcgw"):
    key = (name, auth, priv)
    if key not in _users:   # password_to_key hashes 1 MiB, so cache users across tests
        _users[key] = UsmUser.create(name, auth, "authpass123" if auth != "NONE" else None,
                                     priv, "privpass123" if priv != "NONE" else None)
    return _users[key]


def engine(*users, replay=True):
    return SnmpV3Engine(GW_ENGINE, 5, list(users), R, replay_protection=replay)


class KeyTests(unittest.TestCase):
    def test_rfc3414_a3_vectors(self):
        eid = bytes.fromhex("000000000000000000000002")
        ku = password_to_key(b"maplesyrup", hashlib.md5)
        self.assertEqual(ku.hex(), "9faf3283884e92834ebc9847d8edd963")
        self.assertEqual(localize_key(ku, eid, hashlib.md5).hex(), "526f5eed9fcce26f8964c2930787d82b")
        ku = password_to_key(b"maplesyrup", hashlib.sha1)
        self.assertEqual(ku.hex(), "9fb5cc0381497b3793528939ff788d5d79145211")
        self.assertEqual(localize_key(ku, eid, hashlib.sha1).hex(), "6695febc9288e36282235fc7151f128497b38f3f")

    def test_des_known_answer(self):
        from snmp2opcua.usm import _ciphers
        Cipher, _, modes, TripleDES = _ciphers()
        enc = Cipher(TripleDES(bytes.fromhex("0123456789abcdef") * 3), modes.ECB()).encryptor()
        self.assertEqual((enc.update(b"Now is the time for all ") + enc.finalize()).hex(),
                         "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53")  # FIPS 81

    def test_cfb_matches_library(self):
        from snmp2opcua.usm import _aes_cfb128, _ciphers
        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.modes import CFB
        Cipher, algorithms, _, _ = _ciphers()
        for n in (0, 1, 16, 33, 500):
            key, iv, pt = os.urandom(32), os.urandom(16), os.urandom(n)
            ref = Cipher(algorithms.AES(key), CFB(iv)).encryptor()
            self.assertEqual(_aes_cfb128(key, iv, pt, False), ref.update(pt) + ref.finalize())

    def test_key_extension(self):
        b = user("MD5", "AES256").priv_key(DEVICE_ENGINE)
        r = user("MD5", "AES256C").priv_key(DEVICE_ENGINE)
        self.assertEqual((len(b), len(r)), (32, 32))
        self.assertEqual(b[:16], r[:16])        # both start with the normal localized key
        self.assertNotEqual(b[16:], r[16:])     # and extend it differently
        kul = localize_key(password_to_key(b"privpass123", hashlib.md5), DEVICE_ENGINE, hashlib.md5)
        self.assertEqual(b, kul + hashlib.md5(kul).digest())   # Blumenthal: Kul || H(Kul)

    def test_user_validation(self):
        with self.assertRaises(ValueError):
            UsmUser.create("u", "SHA", "short")
        with self.assertRaises(ValueError):
            UsmUser.create("u", "NONE", None, "AES", "privpass123")
        with self.assertRaises(ValueError):
            UsmUser.create("u", "SHA999", "authpass123")
        self.assertEqual(UsmUser.create("u", "sha-1", "authpass123").auth.name, "SHA")


class EngineTests(unittest.TestCase):
    def test_every_auth_priv_combination(self):
        for auth in ["NONE"] + list(AUTH_PROTOCOLS):
            for priv in ["NONE"] + list(PRIV_PROTOCOLS):
                if auth == "NONE" and priv != "NONE":
                    continue
                with self.subTest(auth=auth, priv=priv):
                    u = user(auth, priv)
                    pkt = build_v3(u, DEVICE_ENGINE, 3, 1000, "linkDown", 42, VBS, context_name=b"ctx")
                    trap, reply = engine(u).handle(pkt, SRC)
                    self.assertIsNone(reply)
                    self.assertEqual((trap.version, trap.trap_name, trap.uptime), ("v3", "linkDown", 42))
                    self.assertEqual((trap.security_name, trap.security_level, trap.engine_id, trap.context_name),
                                     ("opcgw", u.level, DEVICE_ENGINE.hex(), "ctx"))
                    self.assertEqual([(v.name, v.value) for v in trap.varbinds],
                                     [("ifIndex.3", 3), ("ifDescr.3", "Gi0/3")])
                    if priv != "NONE":
                        self.assertNotIn(b"Gi0/3", pkt)    # really encrypted

    def test_wrong_keys_and_tampering(self):
        good = user()
        bad_auth = UsmUser.create("opcgw", "SHA256", "otherpass1", "AES", "privpass123")
        bad_priv = UsmUser.create("opcgw", "SHA256", "authpass123", "AES", "otherpass1")
        e = engine(good)
        with self.assertRaisesRegex(V3Rejected, "authentication failed"):
            e.handle(build_v3(bad_auth, DEVICE_ENGINE, 1, 10, "linkDown", 1, VBS), SRC)
        with self.assertRaisesRegex(V3Rejected, "decryption failed"):
            e.handle(build_v3(bad_priv, DEVICE_ENGINE, 1, 11, "linkDown", 1, VBS), SRC)
        pkt = bytearray(build_v3(good, DEVICE_ENGINE, 1, 12, "linkDown", 1, VBS))
        pkt[-3] ^= 0x01
        with self.assertRaisesRegex(V3Rejected, "authentication failed"):
            e.handle(bytes(pkt), SRC)
        with self.assertRaisesRegex(V3Rejected, "unknown SNMPv3 user"):
            e.handle(build_v3(user(name="intruder"), DEVICE_ENGINE, 1, 13, "linkDown", 1, VBS), SRC)
        with self.assertRaisesRegex(V3Rejected, "configured for authPriv"):
            e.handle(build_v3(user("SHA256", "NONE"), DEVICE_ENGINE, 1, 14, "linkDown", 1, VBS), SRC)
        self.assertEqual((e.counters["wrongDigests"], e.counters["decryptionErrors"],
                          e.counters["unknownUserNames"], e.counters["unsupportedSecLevels"]), (2, 1, 1, 1))

    def test_replay_protection(self):
        u = user()
        e = engine(u)
        e.handle(build_v3(u, DEVICE_ENGINE, 7, 5000, "linkDown", 1, VBS), SRC)
        e.handle(build_v3(u, DEVICE_ENGINE, 7, 4900, "linkDown", 1, VBS), SRC)   # within 150 s window: OK
        with self.assertRaisesRegex(V3Rejected, "stale"):
            e.handle(build_v3(u, DEVICE_ENGINE, 7, 4000, "linkDown", 1, VBS), SRC)
        with self.assertRaisesRegex(V3Rejected, "stale"):
            e.handle(build_v3(u, DEVICE_ENGINE, 6, 9999, "linkDown", 1, VBS), SRC)  # older boots
        e.handle(build_v3(u, DEVICE_ENGINE, 8, 1, "linkDown", 1, VBS), SRC)         # device rebooted properly
        relaxed = engine(u, replay=False)
        relaxed.handle(build_v3(u, DEVICE_ENGINE, 7, 5000, "linkDown", 1, VBS), SRC)
        relaxed.handle(build_v3(u, DEVICE_ENGINE, 7, 1, "linkDown", 1, VBS), SRC)

    def test_engine_id_pinning(self):
        pinned = UsmUser.create("opcgw", "SHA256", "authpass123", "AES", "privpass123",
                                engine_ids=[DEVICE_ENGINE.hex()])
        e = engine(pinned)
        e.handle(build_v3(pinned, DEVICE_ENGINE, 1, 1, "linkDown", 1, VBS), SRC)
        with self.assertRaisesRegex(V3Rejected, "not allowed"):
            e.handle(build_v3(pinned, bytes.fromhex("8000000903112233445566"), 1, 1, "linkDown", 1, VBS), SRC)

    def test_discovery_report(self):
        e = engine(user())
        trap, reply = e.handle(discovery_probe(msg_id=777), SRC)
        self.assertIsNone(trap)
        h, tag, _, stat = read_v3_reply(reply, user())
        self.assertEqual((tag, stat, h.msg_id, h.engine_id, h.boots, h.level),
                         (PDU_REPORT, "unknownEngineIDs", 777, GW_ENGINE, 5, "noAuthNoPriv"))

    def test_inform_response_and_time_window(self):
        for auth, priv in [("SHA256", "AES"), ("MD5", "DES"), ("SHA", "NONE"), ("SHA512", "AES256C")]:
            with self.subTest(auth=auth, priv=priv):
                u = user(auth, priv)
                e = engine(u)
                pkt = build_v3(u, GW_ENGINE, 5, e.engine_time(), "coldStart", 9, VBS, inform=True,
                               request_id=4242, msg_id=99)
                trap, reply = e.handle(pkt, SRC)
                self.assertEqual(trap.pdu, "inform")
                h, tag, rid, _ = read_v3_reply(reply, u)   # verifies MAC and decrypts
                self.assertEqual((tag, rid, h.msg_id, h.level), (PDU_GET_RESPONSE, 4242, 99, u.level))
                # wrong boots -> authenticated notInTimeWindows report carrying our boots/time
                with self.assertRaises(V3Rejected) as ctx:
                    e.handle(build_v3(u, GW_ENGINE, 4, 0, "coldStart", 9, VBS, inform=True), SRC)
                h, tag, _, stat = read_v3_reply(ctx.exception.reply, u)
                self.assertEqual((tag, stat, h.boots, h.level), (PDU_REPORT, "notInTimeWindows", 5, "authNoPriv"))

    def test_authnopriv_time_sync_probe_for_authpriv_user(self):
        full = user("SHA256", "AES")
        probe_user = UsmUser.create("opcgw", "SHA256", "authpass123")   # same auth key, no priv
        e = engine(full)
        # out-of-window authNoPriv probe -> authenticated notInTimeWindows report (not a level error)
        with self.assertRaises(V3Rejected) as ctx:
            e.handle(build_v3(probe_user, GW_ENGINE, 0, 0, "coldStart", 1, [], inform=True), SRC)
        _, tag, _, stat = read_v3_reply(ctx.exception.reply, full)
        self.assertEqual((tag, stat), (PDU_REPORT, "notInTimeWindows"))
        # in-window authNoPriv notification is still refused for an authPriv user
        with self.assertRaisesRegex(V3Rejected, "configured for authPriv") as ctx:
            e.handle(build_v3(probe_user, GW_ENGINE, 5, e.engine_time(), "coldStart", 1, [], inform=True), SRC)
        self.assertEqual(read_v3_reply(ctx.exception.reply, full)[3], "unsupportedSecLevels")

    def test_garbage_never_crashes(self):
        u = user()
        e = engine(u)
        good = build_v3(u, DEVICE_ENGINE, 1, 1, "linkDown", 1, VBS)
        rng = random.Random(7)
        samples = [good[:i] for i in range(len(good))]
        for _ in range(3000):
            b = bytearray(good)
            for _ in range(rng.randint(1, 3)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            samples.append(bytes(b))
        for s in samples:
            try:
                e.handle(s, SRC)
            except (V3Rejected, UsmError, ber.BerError, UnsupportedMessage):
                pass


class StateAndConfigTests(unittest.TestCase):
    def test_engine_state_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            f = str(Path(d) / "engine.json")
            e1, b1 = load_engine_state(f, None)
            e2, b2 = load_engine_state(f, None)
            self.assertEqual((e1, b1, b2), (e2, 1, 2))
            e3, b3 = load_engine_state(f, "80001f8805aabbccdd")
            self.assertEqual((e3.hex(), b3), ("80001f8805aabbccdd", 1))

    def test_config_env_and_validation(self):
        os.environ["T_AUTH"] = "envauthpass"
        cfg = load_config(None)
        cfg["snmp"]["v3"]["users"] = [{"name": "a", "auth_protocol": "SHA", "auth_key": "${T_AUTH}"}]
        self.assertEqual(build_v3_users(cfg)[0].auth_ku, password_to_key(b"envauthpass", hashlib.sha1))
        cfg["snmp"]["v3"]["users"] = [{"name": "a", "auth_protocol": "SHA", "auth_key": "${T_MISSING_VAR}"}]
        with self.assertRaisesRegex(ValueError, "T_MISSING_VAR"):
            build_v3_users(cfg)


class FakePublisher:
    def __init__(self):
        self.traps = []

    async def start(self):
        pass

    async def publish(self, trap):
        self.traps.append(trap)

    async def update_status(self, stats):
        pass

    async def stop(self):
        pass


class EndToEndV3(unittest.IsolatedAsyncioTestCase):
    async def test_udp_v3(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        tmp = tempfile.TemporaryDirectory()
        cfg = load_config(None)
        cfg["snmp"].update(listen_host="127.0.0.1", listen_port=port, versions=["v3"])
        cfg["snmp"]["v3"]["state_file"] = str(Path(tmp.name) / "engine.json")
        cfg["snmp"]["v3"]["_users"] = [user(), user("MD5", "DES", "legacy")]
        pub = FakePublisher()
        gw = Gateway(cfg, publisher=pub)
        task = asyncio.create_task(gw.run())
        await asyncio.sleep(0.2)
        addr = ("127.0.0.1", port)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(build_v3(user(), DEVICE_ENGINE, 1, 100, "linkDown", 7, VBS), addr)
                sock.sendto(build_v3(user("MD5", "DES", "legacy"), DEVICE_ENGINE, 1, 101, "linkUp", 7, []), addr)
                from snmp2opcua.sendtrap import build_v2
                sock.sendto(build_v2("public", "coldStart", 1, []), addr)          # v2c disabled -> rejected
            loop = asyncio.get_running_loop()

            def inform():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    return send_v3_inform(sock, addr, user(), "warmStart", 5, VBS)
            result = await loop.run_in_executor(None, inform)
            self.assertIn("acknowledged (authPriv", result)
            for _ in range(40):
                if len(pub.traps) >= 3:
                    break
                await asyncio.sleep(0.05)
        finally:
            gw.stop()
            await asyncio.wait_for(task, 3)
            tmp.cleanup()
        self.assertEqual([(t.trap_name, t.security_name, t.pdu) for t in pub.traps],
                         [("linkDown", "opcgw", "trap"), ("linkUp", "legacy", "trap"),
                          ("warmStart", "opcgw", "inform")])
        self.assertEqual((gw.stats.received, gw.stats.rejected), (3, 1))


if __name__ == "__main__":
    unittest.main()
