from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sast_tool.code_quality_checker import CodeQualityChecker


class TestCodeQualityChecker(unittest.TestCase):
    def test_flake8_detection(self):
        # Close before launching Flake8: Windows locks open temporary files.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "code with spaces.py"
            path.write_text("import os\n", encoding="utf-8")
            issues = CodeQualityChecker().check(path)
        unused = [i for i in issues if i["code"] == "F401"]
        self.assertEqual(len(unused), 1)
        self.assertEqual(unused[0]["lineno"], 1)
        self.assertEqual(unused[0]["col_offset"], 0)

    def test_clean_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "clean.py"
            path.write_text('print("hello")\n', encoding="utf-8")
            self.assertEqual(CodeQualityChecker().check(path), [])

    def test_missing_flake8_is_error(self):
        result = subprocess.CompletedProcess([], 1, "", "No module flake8")
        with patch("subprocess.run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "Flake8 failed"):
                CodeQualityChecker().check(__file__)

    def test_complexity_warning(self):
        code = "def complex_func(x):\n"
        code += "".join(f"    if x == {i}:\n        return {i}\n"
                        for i in range(11))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "complex.py"
            path.write_text(code, encoding="utf-8")
            issues = CodeQualityChecker().check(path)
        self.assertTrue(any(i["code"] == "C901" for i in issues))
