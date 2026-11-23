"""SNMP polling: client, GE MDS Orbit remote RSSI, poller, config and gateway integration."""
import asyncio
import contextlib
import io
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_agent import ORBIT_TABLE, orbit_mib, start_agent  # noqa: E402

from snmp2opcua import ge_orbit
from snmp2opcua.config import load_config
from snmp2opcua.gateway import Gateway
from snmp2opcua.ge_orbit import Remote, format_report, ip_text, read_remotes, rssi_value, split_index
from snmp2opcua.ge_orbit import main as orbit_main
from snmp2opcua.poller import DevicePoller, convert
from snmp2opcua.snmp_client import SnmpClient, SnmpErrorStatus, SnmpTimeout
from snmp2opcua.snmp_driver import DriverConfigError, build_devices
from snmp2opcua.trap import VarBind

REMOTES = [("00:06:3D:12:34:56", "10.10.1.21", -72), ("00:06:3D:12:34:57", "10.10.1.22", -97),
           ("00:06:3D:AB:CD:EF", "10.10.1.23", -64)]


def master_device(port, **poll):
    p = {"community": "public", "port": port, "scan_rate_ms": 200, "timeout_ms": 300, "retries": 0,
         "ge_orbit_remotes": True}
    p.update(poll)
    return {"name": "Master_LN4", "ip": "127.0.0.1", "auto_create_tags": False, "polling": p,
            "tags": [{"name": "SysName", "address": ".1.3.6.1.2.1.1.5.0"},
                     {"name": "Uptime", "address": ".1.3.6.1.2.1.1.3.0", "data_type": "DWord"}]}


def by_rest(updates):
    return {u.path.split(".", 2)[2]: (u.value, u.good) for u in updates}


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.remotes = [(f"00:06:3D:00:00:{i:02X}", f"10.1.1.{i}", -60 - i) for i in range(1, 31)]
        self.agent, self.tr, self.port = await start_agent(orbit_mib(self.remotes), max_bulk=8)

    async def asyncTearDown(self):
        self.tr.close()

    async def test_get_walk_and_bulk_backoff(self):
        c = SnmpClient("127.0.0.1", "public", "2c", self.port, timeout=0.5)
        try:
            vbs = await c.get(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.9.0"])
            self.assertEqual([(v.value, v.type) for v in vbs], [("LN4-MASTER", "Octet String"), (None, "NoSuchObject")])
            rows = await c.walk(f"{ORBIT_TABLE}.6", max_repetitions=20)
            self.assertEqual(len(rows), 30)                        # stops at the end of the column
            self.assertTrue(all(r.oid.startswith(f"{ORBIT_TABLE}.6.") for r in rows))
            reps = [r[2] for r in self.agent.requests if r[0] == 0xA5]
            self.assertEqual(reps[:3], [20, 10, 5])                  # tooBig -> fewer repetitions
        finally:
            c.close()

    async def test_v1_getnext_and_errors(self):
        c = SnmpClient("127.0.0.1", "public", "1", self.port, timeout=0.5)
        try:
            self.assertEqual(len(await c.walk(f"{ORBIT_TABLE}.2")), 30)
            with self.assertRaises(SnmpErrorStatus) as ctx:
                await c.get(["1.3.6.1.2.1.1.9.0"])
            self.assertEqual((ctx.exception.name, ctx.exception.oid), ("noSuchName", "1.3.6.1.2.1.1.9.0"))
            with self.assertRaises(ValueError):
                await c.getbulk(["1.3"])
        finally:
            c.close()

    async def test_timeouts_and_retries(self):
        wrong = SnmpClient("127.0.0.1", "secret", "2c", self.port, timeout=0.2, retries=1)
        with self.assertRaisesRegex(SnmpTimeout, "after 2 attempt"):
            await wrong.get(["1.3.6.1.2.1.1.5.0"])
        wrong.close()
        self.agent.drop = 1
        c = SnmpClient("127.0.0.1", "public", "2c", self.port, timeout=0.2, retries=1)
        self.assertEqual((await c.get(["1.3.6.1.2.1.1.5.0"]))[0].value, "LN4-MASTER")
        self.assertEqual(c.timeouts, 1)
        c.close()
        with self.assertRaises(ValueError):
            SnmpClient("127.0.0.1", version="3")


class OrbitTests(unittest.IsolatedAsyncioTestCase):
    def test_index_ip_and_rssi_parsing(self):
        self.assertEqual(split_index("3.0.6.61.18.52.86"), (3, "00:06:3D:12:34:56"))
        self.assertIsNone(split_index("3.0.6.61"))
        self.assertIsNone(split_index("3.0.6.61.18.52.999"))
        self.assertEqual(ip_text(VarBind("x", "x", "IpAddress", "10.0.0.5", b"\x0a\x00\x00\x05")), "10.0.0.5")
        self.assertEqual(ip_text(VarBind("x", "x", "Octet String", "0a:00:00:05", b"\x0a\x00\x00\x05")), "10.0.0.5")
        self.assertEqual(ip_text(VarBind("x", "x", "Octet String", "10.0.0.5", b"10.0.0.5")), "10.0.0.5")
        self.assertEqual(ip_text(None), "N/A")
        self.assertEqual(rssi_value(VarBind("x", "x", "Integer32", -72)), -72)
        self.assertEqual(rssi_value(VarBind("x", "x", "Octet String", "-81 dBm")), -81)
        self.assertIsNone(rssi_value(VarBind("x", "x", "Octet String", "n/a")))

    async def test_read_remotes_matches_original_script(self):
        agent, tr, port = await start_agent(orbit_mib(REMOTES, ip_as_octets=False))
        c = SnmpClient("127.0.0.1", "public", "2c", port, timeout=0.5)
        try:
            remotes = await read_remotes(c)
        finally:
            c.close()
            tr.close()
        self.assertEqual([(r.mac, r.ip, r.rssi, r.if_index) for r in remotes],
                         [(m, ip, rssi, 3) for m, ip, rssi in REMOTES])

        # the original script's output, line for line
        expected = [f"{'REMOTE_MAC':<18} {'REMOTE_IP':<16} {'RSSI (dBm)':<12} {'IF_INDEX'}", "-" * 58]
        for mac, ip, rssi in REMOTES:
            expected.append(f"{mac:<18} {ip:<16} {str(rssi):<12} {3}")
        self.assertEqual(format_report(remotes), "\n".join(expected))
        self.assertIn("N/A", format_report([Remote("00:00:00:00:00:01", 1, "N/A", None)]))

    def test_command_line(self):
        ready, info = threading.Event(), {}

        def serve():
            async def run():
                agent, tr, port = await start_agent(orbit_mib(REMOTES))
                info["port"] = port
                ready.set()
                await asyncio.sleep(3)
                tr.close()
            asyncio.run(run())
        threading.Thread(target=serve, daemon=True).start()
        ready.wait(3)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(orbit_main(["--ip", "127.0.0.1", "--port", str(info["port"])]), 0)
        self.assertIn("00:06:3D:12:34:56  10.10.1.21       -72          3", out.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(orbit_main(["--ip", "127.0.0.1", "--port", str(info["port"]), "--community", "x",
                                         "--timeout", "0.2", "--retries", "0"]), 1)
        self.assertIn("Couldn't read 127.0.0.1", err.getvalue())


class ConvertTests(unittest.TestCase):
    def test_conversions(self):
        vb = lambda t, v, raw=b"": VarBind("1.3.6.1", "x", t, v, raw)  # noqa: E731
        self.assertEqual(convert(vb("Integer32", -72), "Long"), -72)
        self.assertEqual(convert(vb("Gauge32", 4294967295), "DWord"), 4294967295)
        self.assertEqual(convert(vb("Octet String", " 42 "), "Long"), 42)
        self.assertEqual(convert(vb("Integer32", 3), "Float"), 3.0)
        self.assertIs(convert(vb("Integer32", 0), "Boolean"), False)
        self.assertIs(convert(vb("Octet String", "up"), "Boolean"), True)
        self.assertEqual(convert(vb("IpAddress", "10.0.0.5", b"\x0a\x00\x00\x05"), "String"), "10.0.0.5")
        self.assertEqual(convert(vb("IpAddress", "10.0.0.5", b"\x0a\x00\x00\x05"), "DWord"), 0x0A000005)
        for bad, dt in [(vb("Integer32", -1), "DWord"), (vb("Counter64", 2**40), "Long"),
                        (vb("NoSuchObject", None), "Long"), (vb("Octet String", "abc"), "Long")]:
            with self.assertRaises(ValueError):
                convert(bad, dt)


class MibConformanceTests(unittest.IsolatedAsyncioTestCase):
    """MDS-IF-LN-MIB::mIfLnStatusConnRemTable as the GE MDS Orbit master defines it."""

    def test_oids_match_the_mib(self):
        # mdsInterfaces = 1.3.6.1.4.1.4130.10.2; mdsIfLnMIB = .5; mIfLnMIBObjects = .1; mIfLnStatus = .2;
        # mIfLnStatusConnRemTable = .2; entry = .1
        self.assertEqual(ge_orbit.BASE_TABLE, "1.3.6.1.4.1.4130.10.2" + ".5.1.2.2.1")
        self.assertEqual((ge_orbit.IP_COL[-2:], ge_orbit.LINK_COL[-2:], ge_orbit.RSSI_COL[-2:]), (".2", ".4", ".6"))
        self.assertEqual(ge_orbit.LINK_STATUS[ge_orbit.ASSOCIATED], "associated")
        self.assertEqual(ge_orbit.LINK_STATUS[5], "disassociated")

    def test_index_and_address_forms(self):
        self.assertEqual(split_index("3.0.6.61.18.52.86"), (3, "00:06:3D:12:34:56"))     # fixed-size MacAddress
        self.assertEqual(split_index("3.6.0.6.61.18.52.86"), (3, "00:06:3D:12:34:56"))   # length sent anyway
        self.assertIsNone(split_index("3.0.6.61.18.52.86.1"))                            # not this table's index
        self.assertIsNone(split_index("3.7.0.6.61.18.52.86"))
        v6 = bytes.fromhex("fd000000000000000000000000000005")
        self.assertEqual(ip_text(VarBind("x", "x", "Octet String", v6.hex(":"), v6)), "fd00::5")
        mapped = bytes(10) + b"\xff\xff" + bytes([10, 0, 0, 5])
        self.assertEqual(ip_text(VarBind("x", "x", "Octet String", mapped.hex(":"), mapped)), "10.0.0.5")
        r = Remote("00:06:3D:12:34:56", 3, "10.0.0.5", -70, 5)
        self.assertEqual((r.link_text, r.associated), ("disassociated", False))
        self.assertEqual((Remote("00:00:00:00:00:01", 1, "", -70).associated, Remote("00:00:00:00:00:01", 1, "", -70, 9).link_text),
                         (None, "unknown(9)"))

    async def test_read_remotes_with_mib_types(self):
        remotes = [("00:06:3D:12:34:56", "10.10.1.21", -72, 4), ("00:06:3D:12:34:57", "fd00::22", -97, 5)]
        for length_prefixed in (False, True):
            _agent, tr, port = await start_agent(orbit_mib(remotes, length_prefixed=length_prefixed))
            c = SnmpClient("127.0.0.1", "public", "2c", port, timeout=0.5)
            try:
                got = await read_remotes(c)
            finally:
                c.close()
                tr.close()
            self.assertEqual([(r.mac, r.ip, r.rssi, r.link_text) for r in got],
                             [("00:06:3D:12:34:56", "10.10.1.21", -72, "associated"),
                              ("00:06:3D:12:34:57", "fd00::22", -97, "disassociated")])

    async def test_link_status_decides_online(self):
        remotes = [REMOTES[0] + (4,), REMOTES[1] + (5,), REMOTES[2] + (4,)]
        agent, tr, port = await start_agent(orbit_mib(remotes))
        dev = build_devices([{"name": "Radios", "devices": [master_device(port)]}])[0]
        p = DevicePoller(dev)
        try:
            v = by_rest(await p.poll_once())
            self.assertEqual(v["Remotes.00063D123457.Online"], (False, True))       # listed, link down
            self.assertEqual(v["Remotes.00063D123457.LinkStatus"], ("disassociated", True))
            self.assertEqual(v["Remotes.00063D123457.RSSI"], (-97, True))
            self.assertEqual(v["Remotes.00063D123457.LastSeen"][1], False)           # never seen linked
            self.assertEqual(v["Remotes.00063D123456.LinkStatus"], ("associated", True))
            self.assertEqual((v["Remotes.Count"], v["Remotes.OnlineCount"]), ((3, True), (2, True)))
            slot = {r["mac"]: r["tag"] for r in p.radios()}["00:06:3D:12:34:57"]
            self.assertEqual(v[f"{slot}_Online"], (False, True))
            row = next(r for r in p.radios() if r["mac"] == "00:06:3D:12:34:57")
            self.assertEqual((row["online"], row["listed"], row["link"]), (False, True, "disassociated"))

            agent.mib = orbit_mib([REMOTES[0] + (4,), REMOTES[1] + (4,)])         # link back; third ages out
            v = by_rest(await p.poll_once())
            self.assertEqual(v["Remotes.00063D123457.Online"], (True, True))
            self.assertTrue(v["Remotes.00063D123457.LastSeen"][1])
            self.assertEqual(v["Remotes.00063DABCDEF.Online"], (False, True))
            row = next(r for r in p.radios() if r["mac"] == "00:06:3D:AB:CD:EF")
            self.assertEqual((row["listed"], row["link"]), (False, "associated"))   # last known link state
        finally:
            p.close()
            tr.close()

    async def test_master_without_link_status(self):
        _agent, tr, port = await start_agent(orbit_mib(REMOTES, link=False))
        dev = build_devices([{"name": "Radios", "devices": [master_device(port)]}])[0]
        p = DevicePoller(dev)
        try:
            v = by_rest(await p.poll_once())
            self.assertEqual(v["Remotes.OnlineCount"], (3, True))                   # listed counts as online
            self.assertEqual(v["Remotes.00063D123456.LinkStatus"], ("", False))     # not reported: Bad quality
        finally:
            p.close()
            tr.close()


class PollerTests(unittest.IsolatedAsyncioTestCase):
    async def test_poll_cycle(self):
        agent, tr, port = await start_agent(orbit_mib(REMOTES))
        dev = build_devices([{"name": "Radios", "devices": [master_device(port, rssi_warning_dbm=-95)]}])[0]
        p = DevicePoller(dev)
        try:
            v = by_rest(await p.poll_once())
            self.assertEqual(v["SysName"], ("LN4-MASTER", True))
            self.assertEqual(v["Uptime"], (123456, True))
            self.assertEqual(v["Remotes.00063D123456.RSSI"], (-72, True))
            self.assertEqual(v["Remotes.00063D123457.IP"], ("10.10.1.22", True))
            self.assertEqual(v["Remotes.00063DABCDEF.MAC"], ("00:06:3D:AB:CD:EF", True))
            self.assertEqual((v["Remotes.Count"], v["Remotes.OnlineCount"], v["_Polling.OK"]),
                             ((3, True), (3, True), (True, True)))
            self.assertEqual({r["mac"]: r["weak"] for r in p.radios()},
                             {"00:06:3D:12:34:56": False, "00:06:3D:12:34:57": True, "00:06:3D:AB:CD:EF": False})

            agent.mib = orbit_mib(REMOTES[:2])                 # one remote drops out
            v = by_rest(await p.poll_once())
            self.assertEqual(v["Remotes.00063DABCDEF.Online"], (False, True))
            self.assertEqual(v["Remotes.00063DABCDEF.RSSI"], (-64, True))   # last value kept
            self.assertEqual(v["Remotes.OnlineCount"], (2, True))

            tr.close()                                          # master stops answering
            v = by_rest(await p.poll_once())
            self.assertEqual(v["_Polling.OK"], (False, True))
            self.assertTrue(v["_Polling.Error"][0])
            self.assertEqual(v["SysName"], ("LN4-MASTER", False))            # Bad quality, last value
            self.assertEqual(v["Remotes.00063D123456.RSSI"], (-72, False))
            self.assertEqual(p.stats.failures, 1)
            self.assertFalse(p.radios()[0]["poll_ok"])
            names = [t[0].split(".", 2)[2] for t in p.static_tags()]
            self.assertEqual(names[:7], ["_Polling.OK", "_Polling.Error", "_Polling.LastPoll", "_Polling.DurationMs",
                                         "_Polling.Failures", "Remotes.Count", "Remotes.OnlineCount"])
            self.assertEqual(names[7:11], ["Remote1", "Remote1_IP", "Remote1_MAC", "Remote1_Online"])
            self.assertEqual((len(names), names[-1]), (7 + 255 * 4, "Remote255_Online"))
        finally:
            p.close()

    async def test_v1_bad_oid_in_batch(self):
        agent, tr, port = await start_agent(orbit_mib(REMOTES))
        dev = build_devices([{"name": "C", "devices": [{
            "name": "D", "ip": "127.0.0.1", "snmp_version": 1, "auto_create_tags": False,
            "polling": {"port": port, "timeout_ms": 300},
            "tags": [{"name": "A", "address": ".1.3.6.1.2.1.1.5.0"},
                     {"name": "Missing", "address": ".1.3.6.1.2.1.1.9.0", "data_type": "Long"},
                     {"name": "B", "address": ".1.3.6.1.2.1.1.3.0", "data_type": "Long"}]}]}])[0]
        p = DevicePoller(dev)
        try:
            v = by_rest(await p.poll_once())
        finally:
            p.close()
            tr.close()
        self.assertEqual((v["A"], v["Missing"], v["B"], v["_Polling.OK"]),
                         (("LN4-MASTER", True), (0, False), (123456, True), (True, True)))


class RemoteNumberingTests(unittest.IsolatedAsyncioTestCase):
    async def poller(self, port, state, **poll):
        dev = build_devices([{"name": "Radios", "devices": [master_device(port, **poll)]}])[0]
        return DevicePoller(dev, state_file=state)

    async def test_stable_numbers_pins_and_persistence(self):
        agent, tr, port = await start_agent(orbit_mib(REMOTES))
        with tempfile.TemporaryDirectory() as d:
            state = Path(d) / "slots.json"
            p = await self.poller(port, state)
            try:
                v = by_rest(await p.poll_once())
                self.assertEqual([v[f"Remote{i}_MAC"][0] for i in (1, 2, 3)], [m for m, _, _ in REMOTES])
                self.assertEqual((v["Remote2"], v["Remote2_IP"], v["Remote2_Online"]),
                                 ((-97, True), ("10.10.1.22", True), (True, True)))
                self.assertEqual((v["Remote4"], v["Remote4_MAC"], v["Remote255_IP"]),
                                 ((0, False), ("", False), ("", False)))           # unused: Bad quality
                self.assertEqual({r["mac"]: r["tag"] for r in p.radios()}["00:06:3D:12:34:57"], "Remote2")

                agent.mib = orbit_mib([REMOTES[0], REMOTES[2]])                    # Remote2 goes offline
                v = by_rest(await p.poll_once())
                self.assertEqual((v["Remote2_MAC"][0], v["Remote2_Online"][0], v["Remote2"][0]),
                                 ("00:06:3D:12:34:57", False, -97))                # keeps its number
                agent.mib = orbit_mib(REMOTES + [("00:06:3D:00:00:99", "10.10.1.99", -70)])
                v = by_rest(await p.poll_once())
                self.assertEqual((v["Remote2_Online"][0], v["Remote4_MAC"][0]), (True, "00:06:3D:00:00:99"))
            finally:
                p.close()

            # after a restart the same radios get the same numbers, even before they're seen
            agent.mib = orbit_mib([REMOTES[2]])
            p2 = await self.poller(port, state)
            try:
                v = by_rest(await p2.poll_once())
                self.assertEqual((v["Remote3_MAC"][0], v["Remote3"][0]), ("00:06:3D:AB:CD:EF", -64))
                self.assertEqual((v["Remote1_MAC"], v["Remote1"]), (("00:06:3D:12:34:56", True), (0, False)))
            finally:
                p2.close()

            # pins by MAC and IP move radios to fixed numbers and reserve them
            agent.mib = orbit_mib(REMOTES)
            p3 = await self.poller(port, state, remote_tags=10, remote_tag_prefix="Radio",
                                   remote_slots={"Radio9": "00063DABCDEF", 1: "10.10.1.22", 5: "00:06:3D:77:77:77"})
            try:
                v = by_rest(await p3.poll_once())
                self.assertEqual(v["Radio9_MAC"][0], "00:06:3D:AB:CD:EF")
                self.assertEqual((v["Radio1_IP"][0], v["Radio1"][0]), ("10.10.1.22", -97))
                self.assertEqual(v["Radio5_MAC"][0], "")                            # reserved for its pin
                self.assertNotIn("Remote1", v)
                self.assertEqual(sorted(p3.slots), [1, 2, 4, 9])
                self.assertEqual(p3.slots[4], "00:06:3D:00:00:99")                  # remembered from the last run
                self.assertEqual(p3.slots[2], "00:06:3D:12:34:56")                  # bumped off 1 by the pin
            finally:
                p3.close()
        tr.close()

    async def test_overflow_and_disabled(self):
        agent, tr, port = await start_agent(orbit_mib(REMOTES))
        p = await self.poller(port, None, remote_tags=2)
        try:
            await p.poll_once()
            self.assertEqual(p.overflow, ["00:06:3D:AB:CD:EF"])
            self.assertEqual({r["mac"]: r["tag"] for r in p.radios()}["00:06:3D:AB:CD:EF"], "")
        finally:
            p.close()
        p = await self.poller(port, None, remote_tags=0)
        try:
            v = by_rest(await p.poll_once())
            self.assertFalse(any(k.startswith("Remote1") for k in v))
            self.assertIn("Remotes.00063D123456.RSSI", v)                          # MAC folders still there
        finally:
            p.close()
            tr.close()

    def test_pin_validation(self):
        def err(**poll):
            with self.assertRaises(DriverConfigError) as ctx:
                build_devices([{"name": "C", "devices": [master_device(161, **poll)]}])
            return str(ctx.exception)
        self.assertIn("not a MAC address", err(remote_slots={1: "radio-7"}))
        self.assertIn("pinned to both", err(remote_slots={1: "10.0.0.1", 2: "10.0.0.1"}))
        self.assertIn("remote_slots key 256", err(remote_slots={256: "10.0.0.1"}))
        self.assertIn("remote tag prefix", err(remote_tag_prefix="Re.mote"))


class PollConfigTests(unittest.TestCase):
    def err(self, **dev):
        base = {"name": "D", "ip": "10.0.0.1"}
        base.update(dev)
        with self.assertRaises(DriverConfigError) as ctx:
            build_devices([{"name": "C", "devices": [base]}])
        return str(ctx.exception)

    def test_validation(self):
        self.assertIn("the rate must be within the range of 10 milliseconds and 49 days.",
                      self.err(polling={"scan_rate_ms": 5}))
        self.assertIn("polling supports SNMP version 1 or 2c",
                      self.err(snmp_version=3, v3={"username": "u"}, polling={"community": "public"}))
        self.assertIn("has no polling settings", self.err(tags=[{"name": "T", "address": ".1.3.6.1.2.1.1.5.0"}]))
        self.assertIn("not supported for polled OIDs",
                      self.err(polling={}, tags=[{"name": "T", "address": ".1.3.6.1.2.1.1.5.0",
                                                  "data_type": "Date"}]))
        dev = build_devices([{"name": "C", "devices": [{"name": "D", "ip": "10.0.0.1", "snmp_version": 3,
                                                       "v3": {"username": "u"},
                                                       "polling": {"snmp_version": "2c",
                                                                   "ge_orbit_remotes": True}}]}])[0]
        self.assertEqual((dev.poll.version, dev.poll.port, dev.poll.scan_rate_ms, dev.poll.ge_orbit_remotes),
                         ("2c", 161, 10000, True))


class RecordingPublisher:
    def __init__(self):
        self.updates = []

    async def start(self):
        pass

    async def publish(self, trap):
        pass

    async def update_status(self, stats):
        pass

    async def stop(self):
        pass

    async def apply_updates(self, updates):
        self.updates.extend(updates)


class GatewayPollingTests(unittest.IsolatedAsyncioTestCase):
    async def test_gateway_polls_and_reports(self):
        agent, tr, aport = await start_agent(orbit_mib(REMOTES))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.yaml"
            udp = 0
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(("127.0.0.1", 0))
                udp = s.getsockname()[1]
            p.write_text(f"snmp: {{listen_host: 127.0.0.1, listen_port: {udp}}}\n"
                         f"channels:\n  - name: Radios\n    devices:\n      - name: Master_LN4\n"
                         f"        ip: 127.0.0.1\n        auto_create_tags: false\n"
                         f"        polling: {{port: {aport}, scan_rate_ms: 150, timeout_ms: 300, "
                         f"ge_orbit_remotes: true}}\n")
            cfg = load_config(p)
        pub = RecordingPublisher()
        gw = Gateway(cfg, publisher=pub)
        seen = []
        gw.monitor = lambda kind, payload: seen.append((kind, payload))
        task = asyncio.create_task(gw.run())
        await asyncio.sleep(0.5)
        gw.stop()
        await asyncio.wait_for(task, 3)
        tr.close()
        self.assertGreaterEqual(sum(1 for r in agent.requests if r[0] == 0xA5), 4)    # polled repeatedly
        paths = {u.path for u in pub.updates}
        self.assertIn("Radios.Master_LN4.Remotes.00063D123456.RSSI", paths)
        self.assertIn("Radios.Master_LN4._Polling.OK", paths)
        radios = [pl for k, pl in seen if k == "radios"]
        self.assertTrue(radios and radios[-1]["ok"] and len(radios[-1]["rows"]) == 3)
        self.assertEqual(gw.engine.values["Radios.Master_LN4.Remotes.00063D123457.RSSI"][0], -97)
        tags = [pl for k, pl in seen if k == "tags"]
        self.assertTrue(any(t[3:] == ("Long", "poll") for batch in tags for t in batch))
        catalog = next(pl for k, pl in seen if k == "catalog")
        paths = {c[0]: c for c in catalog}
        self.assertEqual(paths["Radios.Master_LN4.Remote1"][2:], (False, "Long", "poll"))      # before 1st poll
        self.assertIn("Radios.Master_LN4._Polling.OK", paths)


if __name__ == "__main__":
    unittest.main()
