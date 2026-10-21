import unittest

from sast_tool.vuln_pattern_matcher import VulnPatternMatcher


class TestVulnPatternMatcher(unittest.TestCase):
    def test_hardcoded_password(self):
        for quote in ('"', "'"):
            code = f"password = {quote}lab-only{quote}"
            issues = VulnPatternMatcher().match(code)
            self.assertEqual(len(issues), 1)
            self.assertEqual(issues[0]["type"], "Pattern Match")
            self.assertEqual(issues[0]["col_offset"], 0)

    def test_pickle_import(self):
        for code in ("import pickle", "from pickle import loads"):
            self.assertEqual(len(VulnPatternMatcher().match(code)), 1)

    def test_multiple_lines_and_columns(self):
        issues = VulnPatternMatcher().match(
            'def example():\n    password = "demo"\n    import pickle\n'
        )
        self.assertEqual(
            [(i["lineno"], i["col_offset"]) for i in issues], [(2, 4), (3, 4)]
        )

    def test_custom_pattern(self):
        matcher = VulnPatternMatcher([
            {"pattern": r"\bos\.system\(", "message": "Review shell usage."}
        ])
        self.assertEqual(len(matcher.match('os.system("echo demo")')), 1)

    def test_environment_value_not_flagged(self):
        self.assertEqual(VulnPatternMatcher().match(
            'password = os.environ.get("LAB_PASSWORD")'
        ), [])
