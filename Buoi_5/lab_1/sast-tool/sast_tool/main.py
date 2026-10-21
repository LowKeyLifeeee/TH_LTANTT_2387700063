"""Usage: python -m sast_tool.main examples/vulnerable_01.py."""

import argparse
from pathlib import Path
import tokenize

from sast_tool.ast_analyzer import ASTAnalyzer
from sast_tool.code_quality_checker import CodeQualityChecker
from sast_tool.sarif_reporter import SarifReporter
from sast_tool.security_rule_engine import SecurityRuleEngine
from sast_tool.vuln_pattern_matcher import VulnPatternMatcher


def main(file_path, output_file="report.sarif", rules_file=None):
    if Path(file_path).resolve() == Path(output_file).resolve():
        raise ValueError("Output file must not overwrite the source file.")
    with tokenize.open(file_path) as stream:
        code = stream.read()
    ast_issues = ASTAnalyzer().analyze(code)
    pattern_issues = VulnPatternMatcher().match(code)
    quality_issues = CodeQualityChecker().check(file_path)
    issues = SecurityRuleEngine(rules_file).evaluate(
        ast_issues, pattern_issues, quality_issues
    )
    SarifReporter().generate_report(issues, output_file, file_path)
    print(f"Analysis complete. Report saved to {output_file} "
          f"with {len(issues)} issues.")
    return issues


def cli():
    parser = argparse.ArgumentParser(description="Lab 5.2 Python SAST tool")
    parser.add_argument("file", help="Python source file to analyze")
    parser.add_argument("-o", "--output", default="report.sarif")
    parser.add_argument("--rules", help="Custom JSON severity rules")
    args = parser.parse_args()
    try:
        main(args.file, args.output, args.rules)
    except (OSError, SyntaxError, ValueError, RuntimeError) as error:
        parser.exit(2, f"Analysis failed: {error}\n")


if __name__ == "__main__":
    cli()
