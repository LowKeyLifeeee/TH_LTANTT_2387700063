import json
from pathlib import Path
import tempfile
import unittest

from sast_tool.sarif_reporter import SarifReporter


class TestSarifReporter(unittest.TestCase):
    def test_generate_report(self):
        issues = [{"type": "Use of eval", "message": "Review eval",
                   "lineno": 3, "col_offset": 4, "severity": "high"}]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.sarif"
            source = Path(directory) / "source with spaces.py"
            SarifReporter().generate_report(issues, output, source)
            data = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("$schema", data)
        run = data["runs"][0]
        self.assertEqual(run["columnKind"], "unicodeCodePoints")
        self.assertEqual(run["tool"]["driver"]["name"], "PySAST")
        result = run["results"][0]
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["ruleId"], "Use of eval")
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["region"],
                         {"startLine": 3, "startColumn": 5})
        self.assertEqual(location["artifactLocation"]["uri"], source.as_uri())

    def test_empty_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "empty.sarif"
            SarifReporter().generate_report([], output)
            data = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(data["runs"][0]["results"], [])
