"""Tests for the Diagnostics checks (no Tk needed)."""
import queue
import socket
import tempfile
import time
import unittest
from pathlib import Path

from snmp2opcua.diagnostics import package_version, parse_opc_url, report_text, run_diagnostics, summarize
from snmp2opcua.gui_controller import GatewayController, TrapRequest
from snmp2opcua.usm import UsmUser

BASE = """
snmp:
  listen_host: {host}
  listen_port: {port}
  communities: [{community}]
  v3:
    state_file: {state}
    users: {users}
opcua:
  mode: {mode}
  server:
    endpoint: opc.tcp://127.0.0.1:{opc_port}/gw/
  client:
    url: opc.tcp://127.0.0.1:{opc_port}
    nodes: {{trap_json: "ns=2;s=X"}}
"""
USERS = "[{name: opcgw, auth_protocol: SHA256, auth_key: authpass123, priv_protocol: AES, priv_key: privpass123}]"


def free_port(kind=socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakePublisher:
    def __init__(self, diag=None):
        self.diag = diag

    async def start(self):
        pass

    async def publish(self, trap):
        pass

    async def update_status(self, stats):
        pass

    async def stop(self):
        pass

    def diagnostics(self):
        return self.diag or {}


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.port = free_port()
        self.opc_port = free_port(socket.SOCK_STREAM)
        self.ctls = []

    def tearDown(self):
        for c in self.ctls:
            c.stop()
            c.close()
        self.tmp.cleanup()

    def controller(self, host="127.0.0.1", community="public", users=USERS, mode="server", publisher=None):
        path = self.dir / "config.yaml"
        path.write_text(BASE.format(host=host, port=self.port, community=community, users=users,
                                    state=self.dir / "engine.json", mode=mode, opc_port=self.opc_port))
        ctl = GatewayController(path)
        ctl.publisher_factory = publisher or FakePublisher
        self.ctls.append(ctl)
        return ctl

    @staticmethod
    def find(checks, name):
        hits = [c for c in checks if c.name == name]
        assert hits, f"no check named {name!r}: {[c.name for c in checks]}"
        return hits[0]

    def test_stopped_healthy_ports_and_warnings(self):
        checks = run_diagnostics(self.controller())
        self.assertEqual(self.find(checks, "Configuration").status, "ok")
        udp = self.find(checks, "UDP port")
        self.assertEqual((udp.status, "is free" in udp.result), ("ok", True))
        self.assertEqual(self.find(checks, "Listen address").status, "warn")          # 127.0.0.1
        self.assertEqual(self.find(checks, "Communities").status, "warn")             # 'public'
        self.assertEqual(self.find(checks, "OPC UA server port").status, "ok")
        self.assertEqual(self.find(checks, "Security").status, "warn")                 # NoSecurity
        self.assertEqual(self.find(checks, "State").result, "Stopped")
        expected = "ok" if package_version("asyncua") else "problem"
        self.assertEqual(self.find(checks, "asyncua library").status, expected)

    def test_udp_port_in_use(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blocker:
            blocker.bind(("127.0.0.1", self.port))
            udp = self.find(run_diagnostics(self.controller()), "UDP port")
        self.assertEqual(udp.status, "problem")
        self.assertIn("already in use", udp.result)
        self.assertIn("SNMP Trap", udp.hint)

    def test_opcua_server_port_in_use(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
            blocker.bind(("127.0.0.1", self.opc_port))
            blocker.listen()
            c = self.find(run_diagnostics(self.controller()), "OPC UA server port")
        self.assertEqual((c.status, "in use" in c.result), ("problem", True))

    def test_bad_and_missing_config(self):
        ctl = self.controller()
        ctl.config_path.write_text("opcua: {mode: sideways}")
        c = self.find(run_diagnostics(ctl), "Configuration")
        self.assertEqual(c.status, "problem")
        self.assertIn("Configuration tab", c.hint)
        ctl.config_path = self.dir / "nope.yaml"
        checks = run_diagnostics(ctl)
        self.assertEqual(self.find(checks, "Config file").status, "problem")

    def test_v3_without_users(self):
        c = self.find(run_diagnostics(self.controller(users="[]")), "SNMPv3 users")
        self.assertEqual(c.status, "warn")

    def test_client_mode_reachability(self):
        c = self.find(run_diagnostics(self.controller(mode="client")), "Target server")
        self.assertEqual(c.status, "problem")
        self.assertIn("firewalls", c.hint)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.bind(("127.0.0.1", self.opc_port))
            srv.listen()
            c = self.find(run_diagnostics(self.controller(mode="client")), "Target server")
        self.assertEqual(c.status, "ok")

    def wait(self, ctl, kind, n=1, timeout=4):
        got, end = 0, time.time() + timeout
        while time.time() < end:
            try:
                k, _ = ctl.events.get(timeout=0.05)
            except queue.Empty:
                continue
            got += k == kind
            if got >= n:
                return
        self.fail(f"waited for {n} {kind!r} events")

    def test_running_gateway_with_v3_failures(self):
        ctl = self.controller(host="0.0.0.0", community="plant7")
        ctl.start()
        self.wait(ctl, "started")
        good = ctl.configured_users()[0]
        bad = UsmUser.create("opcgw", "SHA256", "wrongpass1", "AES", "privpass123")
        base = dict(host="127.0.0.1", port=self.port, version="3")
        ctl.send_test_trap(TrapRequest(**base, trap_oid="linkDown", user=good))
        ctl.send_test_trap(TrapRequest(**base, trap_oid="linkDown", user=bad))
        self.wait(ctl, "trap")
        self.wait(ctl, "rejected")
        checks = run_diagnostics(ctl, tk_version="8.6")

        self.assertIn("This gateway is listening", self.find(checks, "UDP port").result)
        self.assertEqual(self.find(checks, "Listen address").status, "ok")
        self.assertEqual(self.find(checks, "Communities").status, "ok")
        self.assertEqual(self.find(checks, "Engine ID").result, ctl._gateway.v3.engine_id.hex())
        auth = self.find(checks, "Messages that failed authentication")
        self.assertEqual((auth.status, auth.result), ("warn", "1"))
        self.assertIn("auth key", auth.hint)
        self.assertEqual(self.find(checks, "Messages that couldn't be decrypted").status, "ok")
        engines = [c for c in checks if c.name.startswith("Device engine ")]
        self.assertEqual(len(engines), 1)
        self.assertIn("last trap", engines[0].result)
        self.assertEqual(self.find(checks, "Queue").status, "ok")
        self.assertIn("1 in the last minute", self.find(checks, "Trap rate").result)
        self.assertEqual(self.find(checks, "Rejected or unreadable").status, "warn")
        self.assertEqual(self.find(checks, "Tk").result, "8.6")
        self.assertIn("OPC UA server", [c.name for c in checks])

        report = report_text(checks)
        self.assertIn("Summary: ", report)
        self.assertIn("Fix: The device's auth key", report)
        for secret in ("authpass123", "privpass123", "wrongpass1"):
            self.assertNotIn(secret, report)

    def test_client_session_state_from_publisher(self):
        diag = {"kind": "client", "connected": False, "targets": 0, "configured_nodes": 1, "connects": 0,
                "write_errors": 2, "last_error": "connection: refused", "last_error_at": "10:00:00"}
        ctl = self.controller(mode="client", publisher=lambda: FakePublisher(diag))
        ctl.start()
        self.wait(ctl, "started")
        checks = run_diagnostics(ctl)
        self.assertEqual(self.find(checks, "Session").status, "problem")
        self.assertEqual(self.find(checks, "Target nodes").status, "warn")
        self.assertEqual(self.find(checks, "Write errors").result, "2")
        self.assertIn("refused", self.find(checks, "Last error").result)

    def test_helpers(self):
        self.assertEqual(parse_opc_url("opc.tcp://10.0.0.5:4841/x"), ("10.0.0.5", 4841))
        self.assertEqual(parse_opc_url("opc.tcp://plc"), ("plc", 4840))
        with self.assertRaises(ValueError):
            parse_opc_url("http://x")
        from snmp2opcua.diagnostics import Check
        self.assertEqual(summarize([Check("s", "a", "ok", "")]), "No problems found")
        self.assertEqual(summarize([Check("s", "a", "problem", ""), Check("s", "b", "warn", ""),
                                    Check("s", "c", "warn", "")]), "1 problem, 2 warnings")


if __name__ == "__main__":
    unittest.main()
