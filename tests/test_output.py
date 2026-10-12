import json
import unittest

from netscope.models import Finding, HostResult, PortResult, ScanReport
from netscope.output import render_grep, render_json, render_text, render_xml


def sample_report() -> ScanReport:
    report = ScanReport(
        tool="netscope", version="2.0.0", command="netscope 127.0.0.1",
        targets=["127.0.0.1"], started=0.0, finished=1.5,
    )
    report.hosts = [HostResult(
        ip="127.0.0.1", hostname="localhost", latency_ms=0.3, os_hint="Linux (Debian)",
        ports=[PortResult(
            port=8000, service="http-alt", category="web",
            product="SimpleHTTP", version="0.6",
            findings=[Finding("LOW", "Cabeceras de seguridad ausentes", "faltan x"),
                      Finding("CRITICAL", "Redis sin autenticación", "")],
        )],
    )]
    report.stats = {"open_ports": 1, "hosts_up": 1}
    return report


class RenderTest(unittest.TestCase):
    def test_json_roundtrip(self):
        data = json.loads(render_json(sample_report()))
        self.assertEqual(data["hosts"][0]["ports"][0]["port"], 8000)

    def test_grep_format(self):
        out = render_grep(sample_report())
        self.assertTrue(out.startswith("Host: 127.0.0.1"))
        self.assertIn("8000/open/tcp", out)

    def test_xml_format(self):
        out = render_xml(sample_report())
        self.assertTrue(out.startswith("<?xml"))
        self.assertIn('portid="8000"', out)
        self.assertIn("netscope-critical", out)

    def test_text_orders_findings_by_severity(self):
        out = render_text(sample_report(), color=False)
        self.assertLess(out.index("Redis sin autenticación"),
                        out.index("Cabeceras de seguridad ausentes"))


if __name__ == "__main__":
    unittest.main()
