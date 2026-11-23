"""Tests for the desktop UI's controller (no Tk needed): a real gateway in a thread, fake OPC UA."""
import queue
import socket
import tempfile
import time
import unittest
from pathlib import Path

from snmp2opcua.gui_controller import GatewayController, TrapRequest, parse_varbind_lines, severity_label

CONFIG = """
snmp:
  listen_host: 127.0.0.1
  listen_port: {port}
  communities: [public]
  v3:
    state_file: {state}
    users:
      - {{name: opcgw, auth_protocol: SHA256, auth_key: authpass123, priv_protocol: AES, priv_key: privpass123}}
traps:
  severity:
    default: 500
    rules: {{linkDown: 800, coldStart: 650}}
"""


class FakePublisher:
    async def start(self):
        pass

    async def publish(self, trap):
        pass

    async def update_status(self, stats):
        pass

    async def stop(self):
        pass


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.port = free_port()
        self.path = Path(self.tmp.name) / "config.yaml"
        self.path.write_text(CONFIG.format(port=self.port, state=Path(self.tmp.name) / "engine.json"))
        self.ctl = GatewayController(self.path)
        self.ctl.publisher_factory = FakePublisher

    def tearDown(self):
        self.ctl.stop()
        self.ctl.close()
        self.tmp.cleanup()

    def wait_for(self, kind, timeout=3.0, seen=None):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                k, payload = self.ctl.events.get(timeout=0.05)
            except queue.Empty:
                continue
            if seen is not None:
                seen.append((k, payload))
            if k == kind:
                return payload
        self.fail(f"no {kind!r} event within {timeout}s")

    def test_full_cycle(self):
        self.ctl.start()
        info = self.wait_for("started")
        self.assertEqual(info["listen"], [f"UDP 127.0.0.1:{self.port}"])
        self.assertEqual(info["mode"], "server")
        self.assertTrue(info["engine_id"])
        users = self.ctl.configured_users()
        self.assertEqual([u.name for u in users], ["opcgw"])

        base = dict(host="127.0.0.1", port=self.port)
        msg = self.ctl.send_test_trap(TrapRequest(**base, version="2c", trap_oid="linkDown",
                                                  varbinds="ifIndex.3 i 3\nifDescr.3 s eth3"))
        self.assertIn("Sent SNMPv2c trap", msg)
        trap = self.wait_for("trap")
        self.assertEqual((trap["trap_name"], trap["severity"], trap["severity_label"]), ("linkDown", 800, "High"))
        self.assertEqual([v["name"] for v in trap["varbinds"]], ["ifIndex.3", "ifDescr.3"])

        self.assertIn("Sent SNMPv3 trap", self.ctl.send_test_trap(
            TrapRequest(**base, version="3", trap_oid="coldStart", user=users[0])))
        trap = self.wait_for("trap")
        self.assertEqual((trap["security_name"], trap["severity_label"]), ("opcgw", "Medium"))

        self.assertIn("acknowledged", self.ctl.send_test_trap(
            TrapRequest(**base, version="3", trap_oid="warmStart", inform=True, user=users[0])))
        self.assertEqual(self.wait_for("trap")["pdu"], "inform")
        self.assertEqual(self.ctl.send_test_trap(TrapRequest(**base, version="2c", inform=True)), "Inform acknowledged")
        self.wait_for("trap")

        self.ctl.send_test_trap(TrapRequest(**base, version="2c", community="wrong"))
        self.assertIn("community", self.wait_for("rejected")["reason"])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"\x30\x03\x02\x01", ("127.0.0.1", self.port))
        self.assertIn("source", self.wait_for("malformed"))

        stats = self.ctl.stats()
        self.assertEqual((stats["received"], stats["rejected"], stats["malformed"]), (4, 1, 1))

        self.ctl.stop()
        self.wait_for("stopped")
        self.assertFalse(self.ctl.running)
        self.assertEqual(self.ctl.stats(), {})

        # restart works and SNMPv3 engine boots goes up
        self.ctl.start()
        self.wait_for("started")
        self.assertEqual(self.ctl._gateway.v3.boots, 2)

    def test_log_lines_reach_ui(self):
        self.ctl.start()
        seen = []
        self.wait_for("started", seen=seen)       # collects the log lines emitted on the way
        logs = [p for k, p in seen if k == "log"]
        self.assertTrue(any("Listening for SNMP traps" in line for _, line in logs))

    def test_port_in_use_reports_error(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", self.port))
        try:
            self.ctl.start()
            self.assertIn("already in use", self.wait_for("error"))
            self.wait_for("stopped")
        finally:
            blocker.close()

    def test_config_validate_and_save(self):
        text = self.ctl.read_text()
        with self.assertRaisesRegex(ValueError, "auth_key"):
            self.ctl.validate_text(text.replace("authpass123", "short"))
        with self.assertRaises(ValueError):
            self.ctl.validate_text("snmp: [unclosed")
        self.assertEqual(self.ctl.validate_text(text)["snmp"]["listen_port"], self.port)
        new = text.replace("default: 500", "default: 400")
        self.ctl.save_text(new)
        self.assertEqual(self.path.read_text(), new)
        self.assertEqual(Path(str(self.path) + ".bak").read_text(), text)
        with self.assertRaises(ValueError):
            self.ctl.save_text("opcua: {mode: sideways}")
        self.assertEqual(self.path.read_text(), new)        # bad config never overwrites a good one

    def test_helpers(self):
        self.assertEqual(parse_varbind_lines("# comment\nifIndex.3 i 3\n\nsysName.0 s my switch\nx.1 n"),
                         [("ifIndex.3", "i", "3"), ("sysName.0", "s", "my switch"), ("x.1", "n", "")])
        for bad in ["ifIndex.3", "ifIndex.3 q 1", "ifIndex.3 uc 1"]:
            with self.assertRaises(ValueError):
                parse_varbind_lines(bad)
        self.assertEqual([severity_label(s) for s in (900, 800, 650, 500)], ["High", "High", "Medium", "Low"])


if __name__ == "__main__":
    unittest.main()
