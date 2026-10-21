"""Run Flake8 in the same Python environment as this tool."""

from pathlib import Path
import subprocess
import sys


class CodeQualityChecker:
    def check(self, filepath):
        path = Path(filepath).resolve(strict=True)
        result = subprocess.run(
            [sys.executable, "-m", "flake8", "--isolated", "--jobs=1",
             "--max-complexity=10",
             "--format=%(row)d:%(col)d:%(code)s:%(text)s", str(path)],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", check=False,
        )
        if result.returncode not in (0, 1) or result.stderr.strip():
            raise RuntimeError(
                "Flake8 failed: " + (result.stderr.strip() or result.stdout)
            )
        issues = []
        for line in result.stdout.splitlines():
            parts = line.split(":", 3)
            if len(parts) != 4:
                raise RuntimeError(f"Unexpected Flake8 output: {line}")
            row, column, code, message = parts
            issues.append({
                "type": "Lint Issue",
                "message": f"{code} {message}",
                "lineno": int(row),
                "col_offset": int(column) - 1,
                "code": code,
            })
        if result.returncode == 1 and not issues:
            raise RuntimeError("Flake8 failed without diagnostics.")
        return issues
