import unittest
from urllib.parse import urlencode
from scanners.sql_injection_tester import SQLInjectionTester


class TestSQL(unittest.TestCase):
    def test_payloads(self):
        for payload in SQLInjectionTester.payloads:
            with self.subTest(payload=payload):
                findings = SQLInjectionTester().scan('http://example.com/?' + urlencode({'id': payload}))
                self.assertEqual(findings[0]['param'], 'id')

    def test_clean(self):
        self.assertEqual(SQLInjectionTester().scan('http://example.com/?id=123'), [])

    def test_case_insensitive(self):
        self.assertTrue(SQLInjectionTester().scan('http://example.com/?' + urlencode({'id': "' or 1=1--"})))
