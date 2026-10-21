import unittest

from sast_tool.ast_analyzer import ASTAnalyzer


class TestASTAnalyzer(unittest.TestCase):
    def test_eval_detection(self):
        issues = ASTAnalyzer().analyze("eval('2+2')")
        self.assertEqual(issues[0]["type"], "Use of eval")
        self.assertEqual(issues[0]["lineno"], 1)
        self.assertEqual(issues[0]["col_offset"], 0)

    def test_exec_detection(self):
        self.assertEqual(
            ASTAnalyzer().analyze("exec(code)")[0]["type"], "Use of exec"
        )

    def test_comments_and_strings_not_calls(self):
        self.assertEqual(ASTAnalyzer().analyze(
            '# eval("x")\ntext = "eval(x)"\nprint(text)\n'
        ), [])

    def test_unicode_column(self):
        code = 'label = "Tiếng Việt"; eval("2")'
        issue = ASTAnalyzer().analyze(code)[0]
        self.assertEqual(issue["col_offset"], code.index("eval"))

    def test_invalid_syntax(self):
        with self.assertRaises(SyntaxError):
            ASTAnalyzer().analyze("def broken(:")
