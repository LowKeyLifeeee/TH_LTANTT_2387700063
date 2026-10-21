import json
from pathlib import Path
import tempfile
import unittest

from sast_tool.security_rule_engine import SecurityRuleEngine


class TestSecurityRuleEngine(unittest.TestCase):
    def test_evaluate(self):
        ast_issues = [{"type": "Use of eval"}]
        patterns = [{"type": "Pattern Match"}]
        quality = [{"type": "Lint Issue"}]
        results = SecurityRuleEngine().evaluate(ast_issues, patterns, quality)
        self.assertEqual([i["severity"] for i in results],
                         ["high", "medium", "low"])
        self.assertNotIn("severity", ast_issues[0])

    def test_custom_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps([
                {"type": "Pattern Match", "severity": "high"}
            ]), encoding="utf-8")
            results = SecurityRuleEngine(path).evaluate(
                [], [{"type": "Pattern Match"}]
            )
        self.assertEqual(results[0]["severity"], "high")

    def test_unknown_issue_retained(self):
        results = SecurityRuleEngine().evaluate([{"type": "Custom"}], [])
        self.assertEqual(results[0]["severity"], "medium")

    def test_invalid_rules_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text('[{"type": "X", "severity": "urgent"}]',
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                SecurityRuleEngine(path)
