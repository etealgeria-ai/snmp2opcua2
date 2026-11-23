"""The config editor must change only what it's asked to and keep every comment."""
import difflib
import unittest
from pathlib import Path

import yaml

from snmp2opcua.yaml_edit import YamlEditError, append_to, delete_in, remove_from, set_in

CONFIG = (Path(__file__).resolve().parent.parent / "config.yaml").read_text()

SMALL = """# top comment
snmp:
  listen_port: 162        # trailing comment
  communities: [public]
channels:
  - name: Radios
    devices:
      - name: Master_LN4   # the LN4 in the MCR
        ip: 192.168.1.10
        polling:
          community: public
          ge_orbit_remotes: true
        # comment inside the device
      - name: Master_B
        ip: 10.0.0.2
        polling: {community: x, ge_orbit_remotes: true}
  - name: Empty
    devices: []
# bottom comment
logging:
  level: INFO
"""


def changed_lines(a: str, b: str) -> list[str]:
    return [ln for ln in difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=0)
            if ln[:1] in "+-" and not ln.startswith(("+++", "---"))]


def comments(text: str) -> list[str]:
    return [ln.split("#", 1)[1].strip() for ln in text.splitlines() if "#" in ln]


def find_device(data, name):
    for ci, ch in enumerate(data["channels"]):
        for di, d in enumerate(ch.get("devices") or []):
            if d["name"] == name:
                return ci, di
    raise KeyError(name)


class YamlEditTests(unittest.TestCase):
    def test_scalar_change_touches_one_line(self):
        out = set_in(SMALL, ["channels", 0, "devices", 0, "ip"], "192.168.1.11")
        self.assertEqual(changed_lines(SMALL, out), ["-        ip: 192.168.1.10", "+        ip: 192.168.1.11"])
        out = set_in(SMALL, ["snmp", "listen_port"], 1162)
        self.assertIn("  listen_port: 1162        # trailing comment", out)

    def test_insert_missing_keys_with_sibling_indentation(self):
        out = set_in(SMALL, ["channels", 0, "devices", 0, "polling", "rssi_warning_dbm"], -95)
        self.assertEqual(yaml.safe_load(out)["channels"][0]["devices"][0]["polling"]["rssi_warning_dbm"], -95)
        self.assertEqual(changed_lines(SMALL, out), ["+          rssi_warning_dbm: -95"])
        out = set_in(out, ["channels", 0, "devices", 0, "trap"], {"enabled": False})
        self.assertEqual(yaml.safe_load(out)["channels"][0]["devices"][0]["trap"], {"enabled": False})
        self.assertEqual(comments(out), comments(SMALL))

    def test_insert_after_trailing_comment(self):
        text = "polling:\n  community: public\n  rssi: -95   # flag weak remotes\nnext: 1\n"
        out = set_in(text, ["polling", "max_repetitions"], 20)
        self.assertEqual(out, "polling:\n  community: public\n  rssi: -95   # flag weak remotes\n"
                              "  max_repetitions: 20\nnext: 1\n")
        seq = "items:\n  - a   # first\nafter: 2\n"
        self.assertEqual(append_to(seq, ["items"], "b"), "items:\n  - a   # first\n  - b\nafter: 2\n")

    def test_flow_mapping_edit(self):
        out = set_in(SMALL, ["channels", 0, "devices", 1, "polling", "community"], "secret")
        self.assertIn("polling: {community: secret, ge_orbit_remotes: true}", out)
        out = set_in(out, ["channels", 0, "devices", 1, "polling", "port"], 1161)
        self.assertEqual(yaml.safe_load(out)["channels"][0]["devices"][1]["polling"],
                         {"community": "secret", "ge_orbit_remotes": True, "port": 1161})

    def test_quoting(self):
        out = set_in(SMALL, ["channels", 0, "devices", 0, "polling", "community"], "pa:ss #1")
        self.assertEqual(yaml.safe_load(out)["channels"][0]["devices"][0]["polling"]["community"], "pa:ss #1")
        out = set_in(out, ["channels", 0, "devices", 0, "polling", "community"], "yes")
        self.assertEqual(yaml.safe_load(out)["channels"][0]["devices"][0]["polling"]["community"], "yes")

    def test_delete(self):
        out = delete_in(SMALL, ["channels", 0, "devices", 0, "polling", "ge_orbit_remotes"])
        self.assertEqual(changed_lines(SMALL, out), ["-          ge_orbit_remotes: true"])
        self.assertEqual(delete_in(SMALL, ["channels", 0, "devices", 0, "nope"]), SMALL)
        out = delete_in(SMALL, ["channels", 0, "devices", 1, "polling", "community"])
        self.assertEqual(yaml.safe_load(out)["channels"][0]["devices"][1]["polling"], {"ge_orbit_remotes": True})

    def test_append_and_remove_devices(self):
        new = {"name": "Master_C", "ip": "10.0.0.3", "polling": {"community": "public", "ge_orbit_remotes": True}}
        out = append_to(SMALL, ["channels", 0, "devices"], new)
        data = yaml.safe_load(out)
        self.assertEqual([d["name"] for d in data["channels"][0]["devices"]], ["Master_LN4", "Master_B", "Master_C"])
        self.assertEqual(data["channels"][0]["devices"][2], new)
        self.assertEqual(comments(out), comments(SMALL))
        out = append_to(out, ["channels", 1, "devices"], {"name": "X", "ip": "10.9.9.9"})   # into []
        self.assertEqual(yaml.safe_load(out)["channels"][1]["devices"], [{"name": "X", "ip": "10.9.9.9"}])

        out2 = remove_from(SMALL, ["channels", 0, "devices"], 0)
        self.assertEqual([d["name"] for d in yaml.safe_load(out2)["channels"][0]["devices"]], ["Master_B"])
        self.assertNotIn("the LN4 in the MCR", out2)                   # its own comments go with it
        self.assertIn("# bottom comment", out2)
        out3 = remove_from(SMALL, ["channels", 0, "devices"], 1)        # last item
        self.assertEqual([d["name"] for d in yaml.safe_load(out3)["channels"][0]["devices"]], ["Master_LN4"])
        self.assertIn("- name: Empty", out3)
        out4 = remove_from(out3, ["channels", 0, "devices"], 0)         # only item -> []
        self.assertEqual(yaml.safe_load(out4)["channels"][0]["devices"], [])
        with self.assertRaises(YamlEditError):
            remove_from(SMALL, ["channels", 0, "devices"], 5)

    def test_new_channel_and_missing_sections(self):
        out = append_to(SMALL, ["channels"], {"name": "Radios2", "devices": [{"name": "M", "ip": "10.1.1.1"}]})
        self.assertEqual(yaml.safe_load(out)["channels"][-1]["devices"][0]["ip"], "10.1.1.1")
        bare = "snmp:\n  listen_port: 162\n"
        out = append_to(bare, ["channels"], {"name": "Radios", "devices": []})
        self.assertEqual(yaml.safe_load(out)["channels"], [{"name": "Radios", "devices": []}])
        out = set_in("snmp:\n  listen_port: 162\nchannels: []\n", ["channels"],
                     [{"name": "R", "devices": [{"name": "M", "ip": "1.2.3.4"}]}])
        self.assertEqual(yaml.safe_load(out)["channels"][0]["devices"][0]["name"], "M")

    def test_real_config_keeps_every_comment(self):
        data = yaml.safe_load(CONFIG)
        ci, di = find_device(data, "Master_LN4")
        base = ["channels", ci, "devices", di]
        out = set_in(CONFIG, base + ["ip"], "10.20.30.40")
        out = set_in(out, base + ["polling", "community"], "ge-read")
        out = set_in(out, base + ["polling", "scan_rate_ms"], 5000)
        out = delete_in(out, base + ["polling", "rssi_warning_dbm"])
        out = set_in(out, base + ["polling", "rssi_warning_dbm"], -90)
        d = yaml.safe_load(out)["channels"][ci]["devices"][di]
        self.assertEqual((d["ip"], d["polling"]["community"], d["polling"]["scan_rate_ms"],
                          d["polling"]["rssi_warning_dbm"]), ("10.20.30.40", "ge-read", 5000, -90))
        lost = set(comments(CONFIG)) - set(comments(out))
        self.assertEqual(lost, {"remotes below this are flagged (window + diagnostics)"})  # the deleted line's
        other = yaml.safe_load(out)
        other["channels"][ci]["devices"][di] = data["channels"][ci]["devices"][di]
        self.assertEqual(other, data)                                   # nothing else changed

        out = append_to(CONFIG, ["channels", ci, "devices"], {"name": "Master_2", "ip": "192.168.1.11",
                                                              "polling": {"community": "public",
                                                                          "ge_orbit_remotes": True}})
        self.assertEqual(set(comments(out)), set(comments(CONFIG)))
        self.assertEqual(yaml.safe_load(out)["channels"][ci]["devices"][-1]["name"], "Master_2")
        back = remove_from(out, ["channels", ci, "devices"], len(yaml.safe_load(out)["channels"][ci]["devices"]) - 1)
        self.assertEqual(yaml.safe_load(back), data)


if __name__ == "__main__":
    unittest.main()
