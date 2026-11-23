"""The Stations page logic: list, validate and save GE master stations without losing comments."""
import difflib
import tempfile
import unittest
from pathlib import Path

import yaml

from snmp2opcua.config import load_config
from snmp2opcua.stations import delete_station, list_stations, lock_numbers, new_station, parse_form, save_station

TEXT = """# radio network
snmp:
  listen_port: 162
channels:
  - name: Radios                 # GE MDS Orbit masters
    devices:
      - name: Master_LN4         # LN4 in the MCR rack
        ip: 192.168.1.10
        snmp_version: 2c
        auto_create_tags: false
        polling:
          community: public      # read-only community
          scan_rate_ms: 10000
          ge_orbit_remotes: true
          rssi_warning_dbm: -95
      - name: Switch1
        ip: 192.168.1.20
  - name: Site2
    devices:
      - name: Master_B
        host: 10.2.0.1
        polling: {community: ro2, ge_orbit_remotes: true, port: 1161}
"""


def form(**over):
    v = {"channel": "Radios", "name": "Master_LN4", "ip": "192.168.1.10", "community": "public", "version": "2c",
         "port": "161", "scan_rate_s": "10", "timeout_ms": "2000", "retries": "1", "max_repetitions": "20",
         "rssi_enabled": True, "rssi_warning_dbm": "-95", "receive_traps": True, "auto_create_tags": False}
    v.update(over)
    return v


def diff(a, b):
    return [ln for ln in difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=0)
            if ln[:1] in "+-" and not ln.startswith(("+++", "---"))]


def loads(text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "c.yaml"
        p.write_text(text)
        return load_config(p)


class RemoteTagFormTests(unittest.TestCase):
    def test_count_prefix_and_lock(self):
        orig = list_stations(TEXT)[0]
        self.assertEqual((orig.remote_tags, orig.remote_tag_prefix), (255, "Remote"))
        st, probs = parse_form(form(remote_tags="255", remote_tag_prefix="Remote"), orig, TEXT)
        self.assertEqual(save_station(TEXT, st, orig), TEXT)                 # defaults aren't written
        st, _ = parse_form(form(remote_tags="64", remote_tag_prefix="Radio"), orig, TEXT)
        out = save_station(TEXT, st, orig)
        p = yaml.safe_load(out)["channels"][0]["devices"][0]["polling"]
        self.assertEqual((p["remote_tags"], p["remote_tag_prefix"]), (64, "Radio"))
        _, probs = parse_form(form(remote_tags="2000", remote_tag_prefix="Re.mote"), orig, TEXT)
        self.assertEqual({f for f, _ in probs}, {"remote_tags", "remote_tag_prefix"})

        locked = lock_numbers(TEXT, orig, {2: "00:06:3D:12:34:57", 1: "10:20:30:40:50:59"})
        pins = yaml.safe_load(locked)["channels"][0]["devices"][0]["polling"]["remote_slots"]
        self.assertEqual(pins, {1: "10:20:30:40:50:59", 2: "00:06:3D:12:34:57"})      # stays a string
        dev = next(d for d in loads(locked)["_devices"] if d.name == "Master_LN4")
        self.assertEqual(dev.poll.remote_slots, {1: "10:20:30:40:50:59", 2: "00:06:3D:12:34:57"})
        self.assertIn("# LN4 in the MCR rack", locked)
        with self.assertRaisesRegex(ValueError, "put the MAC address in quotes"):
            loads(TEXT.replace("          rssi_warning_dbm: -95",
                               "          rssi_warning_dbm: -95\n          remote_slots: {1: 10:20:30:40:50:59}"))


class StationTests(unittest.TestCase):
    def test_list(self):
        sts = list_stations(TEXT)
        self.assertEqual([(s.path, s.ip, s.community, s.port, s.rssi_warning_dbm, s.auto_create_tags) for s in sts],
                         [("Radios.Master_LN4", "192.168.1.10", "public", 161, -95, False),
                          ("Site2.Master_B", "10.2.0.1", "ro2", 1161, None, True)])
        self.assertEqual(new_station(TEXT).name, "Master_1")

    def test_validation_messages(self):
        orig = list_stations(TEXT)[0]
        _, probs = parse_form(form(ip="192.168.1.300", scan_rate_s="0.001", port="0", community="",
                                   retries="x", rssi_warning_dbm="10"), orig, TEXT)
        msgs = dict(probs)
        self.assertIn("Invalid IP address. Enter a valid IPv4 address in quad-dotted notation", msgs["ip"])
        self.assertEqual(msgs["scan_rate_s"], "The rate must be within the range of 10 milliseconds and 49 days.")
        self.assertIn("1 to 65535", msgs["port"])
        self.assertIn("read community", msgs["community"])
        self.assertIn("whole number", msgs["retries"])
        self.assertIn("-200 to 0", msgs["rssi_warning_dbm"])
        _, probs = parse_form(form(name="Switch1"), orig, TEXT)
        self.assertEqual(dict(probs)["name"], "The device Radios.Switch1 has already been added")
        _, probs = parse_form(form(channel="Gateway"), orig, TEXT)
        self.assertIn("reserved", dict(probs)["channel"])
        st, probs = parse_form(form(rssi_enabled=False, rssi_warning_dbm="junk", scan_rate_s="0.5"), orig, TEXT)
        self.assertEqual((probs, st.rssi_warning_dbm, st.scan_rate_ms), ([], None, 500))

    def test_edit_in_place_keeps_comments(self):
        orig = list_stations(TEXT)[0]
        st, _ = parse_form(form(ip="192.168.1.11", scan_rate_s="5", community="ge-read"), orig, TEXT)
        out = save_station(TEXT, st, orig)
        self.assertEqual(sorted(diff(TEXT, out)), sorted([
            "-        ip: 192.168.1.10", "+        ip: 192.168.1.11",
            "-          community: public      # read-only community",
            "+          community: ge-read      # read-only community",
            "-          scan_rate_ms: 10000", "+          scan_rate_ms: 5000"]))
        dev = next(d for d in loads(out)["_devices"] if d.name == "Master_LN4")
        self.assertEqual((dev.host, dev.poll.community, dev.poll.scan_rate_ms), ("192.168.1.11", "ge-read", 5000))

    def test_toggles_rename_and_host_key(self):
        orig = list_stations(TEXT)[0]
        st, _ = parse_form(form(name="Master_North", rssi_enabled=False, receive_traps=False), orig, TEXT)
        out = save_station(TEXT, st, orig)
        d = yaml.safe_load(out)["channels"][0]["devices"][0]
        self.assertEqual((d["name"], d["trap"], "rssi_warning_dbm" in d["polling"]), ("Master_North",
                                                                                     {"enabled": False}, False))
        self.assertIn("# LN4 in the MCR rack", out)
        b = list_stations(TEXT)[1]
        st, _ = parse_form(form(channel="Site2", name="Master_B", ip="10.2.0.9", community="ro2", port="1161",
                                rssi_enabled=False, auto_create_tags=True), b, TEXT)
        out = save_station(TEXT, st, b)
        d = yaml.safe_load(out)["channels"][1]["devices"][0]
        self.assertEqual((d["host"], d["polling"]["port"], d["polling"]["community"]), ("10.2.0.9", 1161, "ro2"))

    def test_add_move_and_delete(self):
        st, probs = parse_form(form(name="Master_2", ip="192.168.1.12", rssi_enabled=False), None, TEXT)
        self.assertEqual(probs, [])
        out = save_station(TEXT, st, None)
        self.assertEqual([s.path for s in list_stations(out)], ["Radios.Master_LN4", "Radios.Master_2",
                                                                "Site2.Master_B"])
        self.assertTrue(set(ln for ln in TEXT.splitlines() if "#" in ln) <= set(out.splitlines()))
        dev = next(d for d in loads(out)["_devices"] if d.name == "Master_2")
        self.assertEqual((dev.host, dev.poll.ge_orbit_remotes, dev.trap_enabled), ("192.168.1.12", True, True))

        st, _ = parse_form(form(channel="Site3", name="Master_3", ip="10.3.0.1"), None, out)
        out2 = save_station(out, st, None)
        self.assertIn("Site3.Master_3", [s.path for s in list_stations(out2)])
        loads(out2)

        orig = list_stations(TEXT)[0]
        st, _ = parse_form(form(channel="Site2"), orig, TEXT)
        moved = save_station(TEXT, st, orig)
        self.assertEqual([s.path for s in list_stations(moved)], ["Site2.Master_B", "Site2.Master_LN4"])
        self.assertEqual(yaml.safe_load(moved)["channels"][0]["devices"][0]["name"], "Switch1")

        gone = delete_station(TEXT, list_stations(TEXT)[1])
        self.assertEqual([s.path for s in list_stations(gone)], ["Radios.Master_LN4"])
        self.assertEqual(yaml.safe_load(gone)["channels"][1]["devices"], [])


if __name__ == "__main__":
    unittest.main()
