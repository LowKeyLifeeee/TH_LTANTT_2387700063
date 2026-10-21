"""Load configurable severity mappings from JSON."""

import json
from pathlib import Path


class SecurityRuleEngine:
    def __init__(self, rules_file=None):
        if rules_file is None:
            rules_file = (
                Path(__file__).resolve().parent.parent
                / "rules" / "default_rules.json"
            )
        with open(rules_file, encoding="utf-8") as stream:
            self.rules = json.load(stream)
        if not isinstance(self.rules, list):
            raise ValueError("Rules must be a JSON list.")
        for rule in self.rules:
            if not isinstance(rule, dict) or not isinstance(
                rule.get("type"), str
            ) or not rule["type"]:
                raise ValueError("Each rule needs a non-empty type.")
            if rule.get("severity", "medium") not in {"low", "medium", "high"}:
                raise ValueError("Severity must be low, medium or high.")

    def evaluate(self, ast_issues, pattern_issues, quality_issues=None):
        issues = []
        for issue in ast_issues + pattern_issues + (quality_issues or []):
            result = dict(issue)
            result.setdefault("severity", "medium")
            for rule in self.rules:
                if rule["type"] == issue["type"]:
                    result["severity"] = rule.get("severity", "medium")
                    break
            issues.append(result)
        return issues
