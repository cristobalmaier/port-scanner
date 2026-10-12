import unittest

from netscope.services import (
    banner_to_text,
    category,
    parse_product_version,
    service_name,
)


class ServiceParsingTest(unittest.TestCase):
    def test_ssh(self):
        product, version = parse_product_version("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
        self.assertEqual(product, "OpenSSH")
        self.assertEqual(version, "8.2p1")

    def test_vsftpd(self):
        product, version = parse_product_version("220 (vsFTPd 3.0.3)")
        self.assertEqual((product, version), ("vsFTPd", "3.0.3"))

    def test_nginx_server_header(self):
        product, version = parse_product_version("nginx/1.18.0")
        self.assertEqual((product, version), ("nginx", "1.18.0"))

    def test_redis_info(self):
        product, version = parse_product_version("redis_version:7.0.5")
        self.assertEqual(version, "7.0.5")

    def test_unknown_banner(self):
        self.assertEqual(parse_product_version("hello world"), ("", ""))

    def test_banner_to_text_strips_noise(self):
        text = banner_to_text(b"220 OK\r\nServer: x\x00y\n")
        self.assertNotIn("\x00", text)
        self.assertIn("220 OK", text)


class KnownPortsTest(unittest.TestCase):
    def test_service_names(self):
        self.assertEqual(service_name(22), "ssh")
        self.assertEqual(service_name(443), "https")
        self.assertEqual(service_name(99999), "unknown")

    def test_udp_names(self):
        self.assertEqual(service_name(53, "udp"), "domain")

    def test_categories(self):
        self.assertEqual(category(443), "web")
        self.assertEqual(category(3306), "database")
        self.assertEqual(category(22), "remote")


if __name__ == "__main__":
    unittest.main()
