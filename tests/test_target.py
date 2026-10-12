import unittest

from netscope.constants import TOP_PORTS
from netscope.target import parse_ports, parse_targets


class ParsePortsTest(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(parse_ports("1-5"), [1, 2, 3, 4, 5])
        self.assertEqual(parse_ports("100-98"), [98, 99, 100])

    def test_all(self):
        self.assertEqual(len(parse_ports("all")), 65535)

    def test_top(self):
        top = parse_ports("top100")
        self.assertLessEqual(len(top), 100)
        self.assertIn(80, top)

    def test_service_name(self):
        self.assertEqual(parse_ports("http"), [80])
        self.assertEqual(parse_ports("ssh,https"), [22, 443])

    def test_default_sorted_unique(self):
        self.assertEqual(parse_ports(None), sorted(set(TOP_PORTS)))


class ParseTargetsTest(unittest.TestCase):
    def test_short_range(self):
        self.assertEqual(parse_targets(["192.168.1.1-3"]),
                         ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    def test_cidr(self):
        hosts = parse_targets(["10.0.0.0/30"])
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2"])

    def test_dedupe(self):
        self.assertEqual(parse_targets(["1.1.1.1", "1.1.1.1"]), ["1.1.1.1"])

    def test_hostname_passthrough(self):
        self.assertEqual(parse_targets(["example.com"]), ["example.com"])


if __name__ == "__main__":
    unittest.main()
