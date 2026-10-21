"""Literal pattern matching; findings require human review."""

import re


class VulnPatternMatcher:
    DEFAULT_PATTERNS = (
        {
            "pattern": r"\bpassword\s*=\s*(['\"])[^\r\n]*?\1",
            "message": "Hardcoded password detected.",
        },
        {
            "pattern": r"\b(?:import\s+pickle\b|from\s+pickle\s+import\b)",
            "message": "Usage of pickle module can be unsafe.",
        },
    )

    def __init__(self, patterns=None):
        self.patterns = (
            self.DEFAULT_PATTERNS if patterns is None else patterns
        )

    def match(self, code: str):
        issues = []
        for pattern in self.patterns:
            for match in re.finditer(pattern["pattern"], code):
                issues.append({
                    "type": "Pattern Match",
                    "message": pattern["message"],
                    "lineno": code.count("\n", 0, match.start()) + 1,
                    "col_offset": (
                        match.start() - code.rfind("\n", 0, match.start()) - 1
                    ),
                })
        return issues
