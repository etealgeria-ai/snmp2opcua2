"""Tests for SNMP-driver style trap tags, Kepware agent traps, tag CSV and the related config checks."""
import asyncio
import io
import socket
import tempfile
import unittest
from pathlib import Path

from snmp2opcua.config import listen_endpoints, load_config
from snmp2opcua.gateway import Gateway
from snmp2opcua.kepware import annotate
from snmp2opcua.oids import OidResolver
from snmp2opcua.receiver import ListenerError, Stats, TrapProtocol
from snmp2opcua.sendtrap import build_v1, build_v2, build_v3, encode_typed, varbind
from snmp2opcua.snmp_driver import (AddressError, DriverConfigError, TrapTagEngine, build_devices, parse_address,
                                    v2_to_v1_identity)
from snmp2opcua.tag_csv import TagCsvError, read_tags, write_tags
from snmp2opcua.trap import parse_message
from snmp2opcua.usm import UsmUser

R = OidResolver()
IP = "192.0.2.50"


def trap_v2(oid, varbinds=(), community="public", ip=IP, uptime=4242):
    return parse_message(build_v2(community, oid, uptime, list(varbinds)), (ip, 5000), R)


def trap_v1(enterprise, generic, specific, varbinds=(), community="public", ip=IP):
    return parse_message(build_v1(community, enterprise, ip, generic, specific, 77, list(varbinds)), (ip, 5000), R)


def device(**over):
    d = {"name": "Switch1", "ip": IP, "snmp_version": "2c", "trap": {"number_of_events": 3, "number_of_fields": 8}}
    d.update(over)
    return d


def engine(*devices):
    return TrapTagEngine(build_devices([{"name": "Channel1", "devices": list(devices)}]))


def values(updates):
    return {u.path.split(".", 2)[2]: u.value for u in updates}


class AddressTests(unittest.TestCase):
    def test_manual_examples(self):
        cases = {
            "TRAP_V1:.1.3.6.1.2.1.11:G2": ("TRAP_V1", 2, None, None, None, "Boolean"),
            "TRAP_V1:.1.3.6.1.2.1.17:G6:S2": ("TRAP_V1", 6, 2, None, None, "Boolean"),
            "TRAP_V1:.1.3.6.1.2.1.11:G2:P3": ("TRAP_V1", 2, None, 3, None, "Boolean"),
            "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3": ("TRAP_V2C", None, None, 3, None, "Boolean"),
            "trap_v2c:1.3.6.1.6.3.1.1.5.3[5]": ("TRAP_V2C", None, None, None, 5, "DWord"),
        }
        for text, (kind, g, s, p, idx, dt) in cases.items():
            a = parse_address(text)
            self.assertEqual((a.kind, a.generic, a.specific, a.port, a.index, a.default_type), (kind, g, s, p, idx, dt))
        self.assertEqual(parse_address("trap_v2c:1.3.6.1.6.3.1.1.5.3[5]").text(), "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3[5]")
        self.assertEqual([parse_address(f"TRAP_V2C:.1.3.6.1.4.1.9.0.1[{i}]").default_type for i in range(1, 9)],
                         ["String", "String", "Long", "Long", "DWord", "Long", "String", "String"])
        self.assertEqual(parse_address("EVENTS_COUNT").default_type, "DWord")
        polled = parse_address(".1.3.6.1.2.1.1.5.0")
        self.assertEqual((type(polled).__name__, polled.oid, polled.text()),
                         ("PollAddress", "1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.5.0"))
        self.assertEqual(parse_address("EVENTS_004_FLDCNT").default_type, "Long")

    def test_rejections_explain_the_fix(self):
        bad = {
            "TRAP_V1:.1.3.6.1.2.1.11": "need :Gx",
            "TRAP_V1:.1.3.6.1.4.1.9:G3": "generic traps use the OID",
            "TRAP_V1:.1.3.6.1.4.1.9:G6": "need :Sx",
            "TRAP_V1:.1.3.6.1.2.1.11:G2:S4": ":S is only used with :G6",
            "TRAP_V1:.1.3.6.1.2.1.11:G9": "0 to 6",
            "TRAP_V2C:.1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss is not implemented",
            "TRAP_V2C:.1.3.6.1.4.1.9:G6:S1": "don't use :G or :S",
            "TRAP_V2C:.1.3.6.1.4.1.9:X1": "unknown field",
            "TRAP_V2C:.1.3.6.1.4.1.4294967296": "4294967295",
            "TRAP_V2C:.1.3.6.1.4.1.9[0]": "table index",
            "EVENTS_000": "start at 001",
            "sysName.0": "Invalid address",
        }
        for text, needle in bad.items():
            with self.assertRaises(AddressError, msg=text) as ctx:
                parse_address(text)
            self.assertIn(needle, str(ctx.exception), text)


class DeviceConfigTests(unittest.TestCase):
    def test_auto_created_tags(self):
        dev = build_devices([{"name": "Channel1", "devices": [device()]}])[0]
        names = {t.name: t for t in dev.tags}
        self.assertEqual(len(dev.tags), 4 * 21 + 1 + 3 * (2 + 8))
        self.assertEqual(names["linkDown"].address.text(), "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3")
        self.assertEqual(names["linkUp_020"].address.text(), "TRAP_V2C:.1.3.6.1.6.3.1.1.5.4[20]")
        self.assertTrue(names["linkDown"].writable and names["EVENTS_COUNT"].writable)
        self.assertFalse(names["linkDown_001"].writable or names["EVENTS_001"].writable)
        v1 = build_devices([{"name": "C", "devices": [device(snmp_version=1)]}])[0]
        self.assertEqual({t.name: t for t in v1.tags}["linkDown"].address.text(), "TRAP_V1:.1.3.6.1.2.1.11:G2")
        none = build_devices([{"name": "C", "devices": [device(auto_create_tags=False)]}])[0]
        self.assertFalse(any(t.name.startswith("link") for t in none.tags))

    def test_user_tag_overrides_auto_name(self):
        dev = build_devices([{"name": "C", "devices": [device(tags=[
            {"name": "linkDown", "address": "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P7", "description": "port 7 only"}])]}])[0]
        tag = next(t for t in dev.tags if t.name == "linkDown")
        self.assertEqual((tag.address.port, tag.auto, tag.description), (7, False, "port 7 only"))

    def test_validation_messages(self):
        def err(channels):
            with self.assertRaises(DriverConfigError) as ctx:
                build_devices(channels)
            return str(ctx.exception)
        self.assertIn("has already been added", err([{"name": "C"}, {"name": "C"}]))
        self.assertIn("has already been added", err([{"name": "C", "devices": [device(), device()]}]))
        self.assertIn("cannot be empty, contain periods",
                      err([{"name": "C", "devices": [device(name="Sw.1")]}]))
        self.assertIn("start with an underscore", err([{"name": "_System", "devices": []}]))
        self.assertIn("Number of Events must be within the range of 1 to 100",
                      err([{"name": "C", "devices": [device(trap={"number_of_events": 101})]}]))
        self.assertIn("Number of Fields must be within the range of 1 to 20",
                      err([{"name": "C", "devices": [device(trap={"number_of_fields": 0})]}]))
        self.assertIn("trap port", err([{"name": "C", "devices": [device(trap={"port": 70000})]}]))
        self.assertIn("UDP or TCP", err([{"name": "C", "devices": [device(trap={"protocol": "SCTP"})]}]))
        self.assertIn("Unable to load username for device C.Switch1",
                      err([{"name": "C", "devices": [device(snmp_version=3)]}]))
        self.assertIn("beyond Number of Events", err([{"name": "C", "devices": [device(tags=[
            {"name": "E9", "address": "EVENTS_009"}])]}]))
        self.assertIn("data type Long is not valid", err([{"name": "C", "devices": [device(tags=[
            {"name": "T", "address": "TRAP_V2C:.1.3.6.1.4.1.9.0.1[8]", "data_type": "Long"}])]}]))
        self.assertIn("has already been added", err([{"name": "C", "devices": [device(tags=[
            {"name": "T", "address": "TRAP_V2C:.1.3.6.1.4.1.9.0.1"}, {"name": "T", "address": "EVENTS_COUNT"}])]}]))


class EngineTests(unittest.TestCase):
    def test_v2c_trap_tags_port_filter_and_table(self):
        eng = engine(device(tags=[
            {"name": "Port3Down", "address": "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3"},
            {"name": "Port4Down", "address": "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P4"},
            {"name": "Port3Name", "address": "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3[10]"},
            {"name": "Beyond", "address": "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3[40]"}]))
        ups = eng.process(trap_v2("linkDown", [varbind("ifIndex.3", encode_typed("i", "3")),
                                               varbind("ifDescr.3", encode_typed("s", "Gi0/3"))]))
        v = values(ups)
        self.assertIs(v["linkDown"], True)                     # base tag also updates (manual)
        self.assertIs(v["Port3Down"], True)
        self.assertNotIn("Port4Down", v)
        self.assertEqual(v["Port3Name"], "Gi0/3")
        self.assertEqual([v[f"linkDown_{i:03d}"] for i in range(2, 9)],
                         ["1.3.6.1.6.3.1.1.5", 2, 0, 4242, 2, "1.3.6.1.2.1.2.2.1.1.3", "3"])
        beyond = next(u for u in ups if u.path.endswith(".Beyond"))
        self.assertEqual((beyond.good, beyond.value), (False, ""))
        self.assertNotIn("coldStart", v)

    def test_v1_generic_and_enterprise(self):
        eng = engine(device(snmp_version=1, tags=[
            {"name": "UpsOnBattery", "address": "TRAP_V1:.1.3.6.1.4.1.318:G6:S5"},
            {"name": "UpsField4", "address": "TRAP_V1:.1.3.6.1.4.1.318:G6:S5[4]"}]))
        v = values(eng.process(trap_v1("1.3.6.1.4.1.9", 2, 0)))
        self.assertIs(v["linkDown"], True)                 # generic traps match whatever the enterprise
        v = values(eng.process(trap_v1("1.3.6.1.4.1.318", 6, 5)))
        self.assertEqual((v["UpsOnBattery"], v["UpsField4"]), (True, 5))
        self.assertNotIn("UpsOnBattery", values(eng.process(trap_v1("1.3.6.1.4.1.318", 6, 6))))

    def test_rfc3584_identity(self):
        self.assertEqual(v2_to_v1_identity(trap_v2("1.3.6.1.4.1.9.9.41.2.0.1")), ("1.3.6.1.4.1.9.9.41.2", 6, 1))
        self.assertEqual(v2_to_v1_identity(trap_v2("1.3.6.1.4.1.9.9.41.2.7")), ("1.3.6.1.4.1.9.9.41.2", 6, 7))
        t = trap_v2("coldStart", [varbind("1.3.6.1.6.3.1.1.4.3.0", encode_typed("o", "1.3.6.1.4.1.311"))])
        self.assertEqual(v2_to_v1_identity(t), ("1.3.6.1.4.1.311", 0, 0))

    def test_device_settings_filter_traps(self):
        eng = engine(device(trap={"community": "plant7"}), device(name="V1only", snmp_version=1),
                     device(name="Off", trap={"enabled": False}))
        ups = eng.process(trap_v2("coldStart", community="public"))
        self.assertEqual(ups, [])
        self.assertIn("Custom Community", eng.state["Channel1.Switch1"].last_reason)
        self.assertIn("SNMP version 1", eng.state["Channel1.V1only"].last_reason)
        ups = eng.process(trap_v2("coldStart", community="plant7"))
        self.assertTrue(ups and all(u.path.startswith("Channel1.Switch1.") for u in ups))
        eng.process(trap_v2("coldStart", ip="198.51.100.1"))
        self.assertEqual(eng.unmatched, {"198.51.100.1": 1})

    def test_v3_device_user(self):
        u = UsmUser.create("upsuser", "SHA", "authpass123", "AES", "privpass123")
        other = UsmUser.create("other", "SHA", "authpass123")
        eng = engine(device(snmp_version=3, v3={"username": "upsuser", "auth_protocol": "SHA",
                                                "auth_passphrase": "authpass123", "priv_protocol": "AES",
                                                "priv_passphrase": "privpass123"}))
        from snmp2opcua.snmpv3 import SnmpV3Engine
        v3 = SnmpV3Engine(b"\x80\x00\x1f\x88\x05gw", 1, [u, other], R)
        t, _ = v3.handle(build_v3(u, b"\x80\x00\x1f\x88\x04dev", 1, 10, "linkUp", 1, []), (IP, 1))
        self.assertIs(values(eng.process(t))["linkUp"], True)
        t, _ = v3.handle(build_v3(other, b"\x80\x00\x1f\x88\x04dev", 1, 11, "linkUp", 1, []), (IP, 1))
        self.assertEqual(eng.process(t), [])
        self.assertIn("not this device's user", eng.state["Channel1.Switch1"].last_reason)

    def test_events_queue(self):
        eng = engine(device(trap={"number_of_events": 2, "number_of_fields": 7}))
        eng.process(trap_v2("coldStart", uptime=1))
        eng.process(trap_v2("warmStart", uptime=2))
        v = values(eng.process(trap_v2("linkDown", [varbind("ifIndex.9", encode_typed("i", "9"))], uptime=3)))
        e1 = v["EVENTS_001"].split(";")
        self.assertEqual(e1[1:], ["1.3.6.1.6.3.1.1.5", "2", "0", "3", "1", "1.3.6.1.2.1.2.2.1.1.9"])  # 7 fields
        self.assertEqual(v["EVENTS_001_FLDCNT"], 7)
        self.assertEqual(v["EVENTS_002_005"], "2")                          # previous trap moved down
        self.assertNotIn("EVENTS_003", v)                                   # queue holds 2
        self.assertEqual(eng.values["Channel1.Switch1.EVENTS_COUNT"][0], 3)
        eng.reset("Channel1.Switch1.EVENTS_COUNT")
        eng.process(trap_v2("coldStart"))
        self.assertEqual(eng.values["Channel1.Switch1.EVENTS_COUNT"][0], 1)

    def test_extended_ascii(self):
        eng = engine(device(trap={"extended_ascii": True}, tags=[
            {"name": "Txt", "address": "TRAP_V2C:.1.3.6.1.4.1.9.0.1[8]"}]))
        v = values(eng.process(trap_v2("1.3.6.1.4.1.9.0.1", [varbind("1.3.6.1.4.1.9.1", encode_typed("x", "c4e9fc"))])))
        self.assertEqual(v["Txt"], "Äéü")

    def test_unresolvable_host(self):
        def fail(_):
            raise OSError("no such host")
        devs = build_devices([{"name": "C", "devices": [device(ip="no-such-host.invalid")]}])
        eng = TrapTagEngine(devs, resolve=fail)
        self.assertIn("Unable to resolve host address no-such-host.invalid", eng.state["C.Switch1"].error)


class KepwareAgentTests(unittest.TestCase):
    def test_v2c_trap_from_kepware_agent(self):
        t = trap_v2("1.3.6.1.4.1.30144.12.4.3.1.2", [
            varbind("1.3.6.1.4.1.30144.12.4.1.7.0", encode_typed("s", "Tank 2 level high")),
            varbind("1.3.6.1.4.1.30144.12.4.1.5.0", encode_typed("s", "KEPSERVER01"))])
        self.assertTrue(annotate(t))
        self.assertEqual((t.description, t.vendor, t.agent_id), ("Tank 2 level high", "Kepware SNMP Agent", 4))
        self.assertEqual([v.name for v in t.varbinds], ["lastTrapDescr", "sysName"])
        self.assertEqual(t.trap_name, "kepwareSnmpAgent.4.3.1.2")
        self.assertIn('"Tank 2 level high"', t.summary())
        self.assertEqual(t.to_dict()["description"], "Tank 2 level high")

    def test_v1_and_non_kepware(self):
        t = trap_v1("1.3.6.1.4.1.30144.12.3", 6, 2)
        self.assertTrue(annotate(t))
        self.assertEqual(t.agent_id, 3)
        plain = trap_v2("linkDown")
        self.assertFalse(annotate(plain))
        self.assertNotIn("vendor", plain.to_dict())


class TagCsvTests(unittest.TestCase):
    KEPWARE_EXPORT = (
        "﻿Tag Name;Address;Data Type;Respect Data Type;Client Access;Scan Rate;Scaling;Raw Low;Raw High;"
        "Scaled Low;Scaled High;Scaled Data Type;Clamp Low;Clamp High;Eng Units;Description;Negate Value\r\n"
        "\"Traps.Port3Down\";\"TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3\";Boolean;1;R/W;100;;;;;;;;;;\"Port 3 down\";\r\n"
        "\"Traps.Port3Down_Uptime\";\"TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3[5]\";DWord;1;RO;100;;;;;;;;;;;\r\n"
        "\"sysUpTime\";\"1.3.6.1.2.1.1.3.0\";DWord;1;RO;1000;;;;;;;;;;;\r\n"
        "\"sysName\";\"sysName.0\";String;1;RO;1000;;;;;;;;;;;\r\n")

    def test_import_kepware_export(self):
        tags, skipped = read_tags(io.StringIO(self.KEPWARE_EXPORT.lstrip("﻿")))
        self.assertEqual([(t.name, t.address.text(), t.data_type) for t in tags],
                         [("Traps.Port3Down", "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3", "Boolean"),
                          ("Traps.Port3Down_Uptime", "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3[5]", "DWord"),
                          ("sysUpTime", ".1.3.6.1.2.1.1.3.0", "DWord")])     # polled OID
        self.assertEqual(tags[0].description, "Port 3 down")
        self.assertEqual(len(skipped), 1)
        self.assertIn("sysName.0", skipped[0])

    def test_any_column_order_and_errors(self):
        text = "Description,Address,Tag Name\nd1,TRAP_V2C:.1.3.6.1.4.1.9.0.1,A\n,TRAP_V1:.1.3.6.1.4.1.9:G3,B\n,,C\n"
        with self.assertRaises(TagCsvError) as ctx:
            read_tags(io.StringIO(text))
        self.assertEqual(len(ctx.exception.problems), 2)
        self.assertIn("Row 3", ctx.exception.problems[0])
        self.assertIn("Row 4: Tag Name and Address are required", ctx.exception.problems[1])
        with self.assertRaises(TagCsvError):
            read_tags(io.StringIO("Name,Where\nx,y\n"))

    def test_round_trip_and_config_reference(self):
        dev = build_devices([{"name": "C", "devices": [device(tags=[
            {"name": "G1.Alarm", "address": "TRAP_V1:.1.3.6.1.2.1.11:G3", "description": "up, again"}],
            snmp_version=1)]}])[0]
        buf = io.StringIO()
        self.assertEqual(write_tags(dev.tags, buf), 1)                    # auto-created tags left out
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "sw1.csv").write_text(buf.getvalue())
            (Path(d) / "config.yaml").write_text(
                "snmp: {listen_port: 1162}\nchannels:\n  - name: C\n    devices:\n      - name: Sw1\n"
                f"        ip: {IP}\n        snmp_version: 1\n        tags_csv: sw1.csv\n")
            cfg = load_config(Path(d) / "config.yaml")
        tag = next(t for t in cfg["_devices"][0].tags if t.name == "G1.Alarm")
        self.assertEqual((tag.address.text(), tag.description), ("TRAP_V1:.1.3.6.1.2.1.11:G3", "up, again"))
        self.assertEqual(cfg["_devices"][0].port, 1162)                   # device port defaults to listen_port


class ConfigChecksTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.yaml"
            p.write_text(text)
            return load_config(p)

    def err(self, text):
        with self.assertRaises(ValueError) as ctx:
            self.load(text)
        return str(ctx.exception)

    def test_messages(self):
        self.assertEqual(self.err("snmp: {communities: [a, a]}"), "The community a has already been added.")
        self.assertEqual(self.err("snmp: {allowed_sources: [10.0.0.1, 10.0.0.1]}"),
                         "The host IP 10.0.0.1 has already been added.")
        self.assertIn("Invalid IP address '10.0.0.300'. Enter a valid IPv4 address in quad-dotted notation",
                      self.err("snmp: {allowed_sources: [10.0.0.300]}"))
        self.assertEqual(self.err("snmp: {network_interfaces: [{address: 0.0.0.0, port: 162}, "
                                  "{address: 0.0.0.0, port: 162}]}"),
                         "The network interface 0.0.0.0; Port: 162 has already been added.")
        self.assertIn("reserved", self.err(f"channels: [{{name: Gateway, devices: [{{name: d, ip: {IP}}}]}}]"))
        self.assertIn("doesn't include v1", self.err(
            f"snmp: {{versions: [v2c]}}\nchannels: [{{name: C, devices: [{{name: d, ip: {IP}, snmp_version: 1}}]}}]"))

    def test_endpoints(self):
        cfg = self.load(f"""
snmp:
  listen_host: 0.0.0.0
  listen_port: 162
  network_interfaces:
    - {{address: 0.0.0.0, port: 162}}
    - {{address: 127.0.0.1, port: 1162}}
channels:
  - name: C
    devices:
      - {{name: a, ip: {IP}}}
      - {{name: b, ip: {IP}, trap: {{port: 10162, protocol: TCP}}}}
""")
        self.assertEqual(listen_endpoints(cfg), [("0.0.0.0", 162, "UDP"), ("127.0.0.1", 1162, "UDP"),
                                                 ("0.0.0.0", 10162, "TCP")])

    def test_accept_all_hosts(self):
        def proto(**kw):
            return TrapProtocol(asyncio.Queue(), Stats(), R, [], kw.pop("sources", []), **kw)
        self.assertTrue(proto()._source_allowed("203.0.113.9"))                       # default: all
        self.assertFalse(proto(sources=["10.0.0.0/8"])._source_allowed("203.0.113.9"))
        self.assertTrue(proto(sources=["10.0.0.0/8"], accept_all_hosts=True)._source_allowed("203.0.113.9"))
        self.assertFalse(proto(accept_all_hosts=False)._source_allowed("10.1.1.1"))


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


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def test_udp_and_tcp_devices(self):
        udp, tcp = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_STREAM)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.yaml"
            p.write_text(f"""
snmp: {{listen_host: 127.0.0.1, listen_port: {udp}, v3: {{state_file: {d}/e.json}}}}
channels:
  - name: Channel1
    devices:
      - {{name: Switch1, ip: 127.0.0.1}}
      - name: Ups1
        ip: 127.0.0.1
        snmp_version: 3
        auto_create_tags: false
        trap: {{port: {tcp}, protocol: TCP}}
        v3: {{username: ups, auth_protocol: SHA, auth_passphrase: authpass123}}
        tags: [{{name: OnBattery, address: "TRAP_V2C:.1.3.6.1.2.1.33.2.0.1"}}]
""")
            cfg = load_config(p)
        pub = FakePublisher()
        gw = Gateway(cfg, publisher=pub)
        seen = []
        gw.monitor = lambda kind, payload: seen.append((kind, payload))
        task = asyncio.create_task(gw.run())
        await asyncio.sleep(0.2)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(build_v2("public", "linkDown", 9, [varbind("ifIndex.2", encode_typed("i", "2"))]),
                         ("127.0.0.1", udp))
            u = UsmUser.create("ups", "SHA", "authpass123")
            pkt = build_v3(u, b"\x80\x00\x1f\x88\x04ups", 1, 5, "upsTrapOnBattery", 1, [])
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp)
            writer.write(pkt[:7])
            await writer.drain()
            await asyncio.sleep(0.05)
            writer.write(pkt[7:] + pkt)          # rest of the first message, then a second one
            await writer.drain()
            for _ in range(40):
                if len(pub.traps) >= 3:
                    break
                await asyncio.sleep(0.05)
            writer.close()
        finally:
            gw.stop()
            await asyncio.wait_for(task, 3)
        self.assertEqual([t.trap_name for t in pub.traps], ["linkDown", "upsTrapOnBattery", "upsTrapOnBattery"])
        self.assertIn("Channel1.Switch1.linkDown", {u.path for u in pub.traps[0].tag_updates})
        self.assertIn("Channel1.Ups1.OnBattery", {u.path for u in pub.traps[1].tag_updates})
        self.assertEqual(gw.engine.values["Channel1.Ups1.EVENTS_COUNT"][0], 2)
        started = next(p for k, p in seen if k == "started")
        self.assertEqual(started["listen"], [f"UDP 127.0.0.1:{udp}", f"TCP 127.0.0.1:{tcp}"])
        tag_events = [p for k, p in seen if k == "tags"]
        self.assertTrue(any(("Channel1.Switch1.linkDown", True, True, "Boolean", "trap") in ev for ev in tag_events))
        catalog = {c[0]: c for c in next(p for k, p in seen if k == "catalog")}
        self.assertEqual(catalog["Channel1.Switch1.linkDown"][1:], (False, True, "Boolean", "trap"))
        self.assertEqual(catalog["Channel1.Ups1.EVENTS_COUNT"][3:], ("DWord", "trap"))

    async def test_listener_error_wording(self):
        port = free_port(socket.SOCK_DGRAM)
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", port))
        cfg = load_config(None)
        cfg["snmp"].update(listen_host="127.0.0.1", listen_port=port)
        try:
            with self.assertRaises(ListenerError) as ctx:
                await Gateway(cfg, publisher=FakePublisher()).run()
        finally:
            blocker.close()
        self.assertIn(f"Unable to bind trap socket on binding address 127.0.0.1, port {port} and protocol UDP",
                      ctx.exception.strerror)
        self.assertIn("Windows SNMP Trap service", ctx.exception.strerror)


if __name__ == "__main__":
    unittest.main()
