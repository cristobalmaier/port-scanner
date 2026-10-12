import unittest

from netscope.vulns import (
    STATIC_PORT_FINDINGS,
    compare_versions,
    match_cves,
    static_findings,
    version_tuple,
)


class VersionCompareTest(unittest.TestCase):
    def test_order(self):
        self.assertEqual(compare_versions("2.4.49", "2.4.50"), -1)
        self.assertEqual(compare_versions("3.0.3", "3.0.3"), 0)
        self.assertEqual(compare_versions("9.8p1", "9.7"), 1)

    def test_tuple_ignores_text(self):
        self.assertEqual(version_tuple("8.5p1"), (8, 5, 1))
        self.assertEqual(version_tuple("v2.0.0"), (2, 0, 0))


class CveMatchingTest(unittest.TestCase):
    def test_vsftpd_backdoor(self):
        cves = [f.title for f in match_cves("vsFTPd", "2.3.4")]
        self.assertTrue(any("CVE-2011-2523" in c for c in cves))

    def test_regresshion_in_range(self):
        cves = [f.title for f in match_cves("OpenSSH", "9.0p1")]
        self.assertTrue(any("CVE-2024-6387" in c for c in cves))

    def test_regresshion_out_of_range(self):
        cves = [f.title for f in match_cves("OpenSSH", "9.8p1")]
        self.assertFalse(any("CVE-2024-6387" in c for c in cves))

    def test_apache_path_traversal(self):
        cves = [f.title for f in match_cves("Apache", "2.4.49")]
        self.assertTrue(any("CVE-2021-41773" in c for c in cves))

    def test_no_false_positive(self):
        self.assertEqual(match_cves("nginx", "1.25.3"), [])


class StaticFindingsTest(unittest.TestCase):
    def test_telnet_is_critical(self):
        findings = static_findings(23)
        self.assertEqual(findings[0].level, "CRITICAL")

    def test_unknown_port(self):
        self.assertEqual(static_findings(12345), [])

    def test_all_levels_valid(self):
        for finding in STATIC_PORT_FINDINGS.values():
            self.assertIn(finding.level, {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})


if __name__ == "__main__":
    unittest.main()
