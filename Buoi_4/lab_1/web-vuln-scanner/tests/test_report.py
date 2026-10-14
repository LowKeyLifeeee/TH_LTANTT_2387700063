import unittest
from report.report_generator import ReportGenerator


class TestReport(unittest.TestCase):
    def test_flatten(self):
        result = ReportGenerator().generate([[{'type': 'XSS'}], {'type': 'SSRF'}])
        self.assertEqual(result['summary']['total'], 2)

    def test_information_is_not_vulnerability(self):
        result = ReportGenerator().generate([{'csrf_protected': True}])
        self.assertEqual(result['vulnerabilities'], [])

    def test_errors_are_visible(self):
        result = ReportGenerator().generate([], ['timeout'])
        self.assertFalse(result['summary']['complete'])
