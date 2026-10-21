import tempfile
from pathlib import Path
import unittest
from security_behavior_checker import SecurityBehaviorChecker


class TestSecurityBehaviorChecker(unittest.TestCase):
    def test_default_matches_rule_literals(self):
        self.assertEqual(SecurityBehaviorChecker().suspicious_calls(), ['os.system', 'eval', 'exec'])

    def test_source_is_read_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'example.py'
            path.write_text('raise RuntimeError()\n# eval', encoding='utf-8')
            self.assertEqual(SecurityBehaviorChecker().suspicious_calls(path), ['eval'])
            path.write_text('print(123)', encoding='utf-8')
            self.assertEqual(SecurityBehaviorChecker().suspicious_calls(path), [])
