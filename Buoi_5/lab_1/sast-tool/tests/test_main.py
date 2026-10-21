import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from sast_tool.main import main


class TestMain(unittest.TestCase):
    def test_scan_never_executes_target(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "target.py"
            output = Path(directory) / "report.sarif"
            source.write_text(
                'raise RuntimeError("must not execute")\neval("2+2")\n',
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                issues = main(source, output)
            self.assertTrue(any(i["type"] == "Use of eval" for i in issues))
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(data["runs"][0]["results"]), len(issues))

    def test_source_cannot_be_overwritten(self):
        with self.assertRaisesRegex(ValueError, "overwrite"):
            main(__file__, __file__)

    def test_syntax_error_does_not_create_report(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bad.py"
            output = Path(directory) / "report.sarif"
            source.write_text("def broken(:", encoding="utf-8")
            with self.assertRaises(SyntaxError):
                main(source, output)
            self.assertFalse(output.exists())
