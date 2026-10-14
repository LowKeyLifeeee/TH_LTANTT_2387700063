import unittest
from unittest.mock import patch, Mock
from urllib.parse import parse_qs, urlsplit
import requests
from scanners.xss_scanner import XSSScanner


class TestXSS(unittest.TestCase):
    @patch('scanners.xss_scanner.requests.get')
    def test_reflection_and_preserved_query(self, get):
        get.side_effect = lambda url, **kwargs: Mock(status_code=200, text=parse_qs(urlsplit(url).query)['q'][0])
        findings = XSSScanner().scan('http://example.com/?q=hello&id=42')
        self.assertEqual(len(findings), 2)
        self.assertEqual(parse_qs(urlsplit(findings[0]['url']).query)['id'], ['42'])

    @patch('scanners.xss_scanner.requests.get')
    def test_encoded_response(self, get):
        get.return_value = Mock(status_code=200, text='&lt;script&gt;alert(1)&lt;/script&gt;')
        self.assertEqual(XSSScanner().scan('http://example.com/'), [])

    @patch('scanners.xss_scanner.requests.get', side_effect=requests.Timeout('timeout'))
    def test_network_error(self, get):
        scanner = XSSScanner()
        self.assertEqual(scanner.scan('http://example.com/'), [])
        self.assertEqual(len(scanner.errors), 2)
