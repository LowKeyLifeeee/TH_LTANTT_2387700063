import unittest
from urllib.parse import urlencode
from scanners.ssrf_tester import SSRFTester


class TestSSRF(unittest.TestCase):
    def test_internal_addresses(self):
        for host in ['127.0.0.1', 'localhost', '10.0.0.1', '172.16.0.1', '192.168.1.1', '[::1]', '169.254.169.254']:
            with self.subTest(host=host):
                self.assertTrue(SSRFTester().scan('http://example.com/?' + urlencode({'url': 'http://' + host})))

    def test_public_and_misleading_hosts(self):
        for value in ['http://example.com', 'http://127.0.0.1.example.com', 'http://example.com/localhost']:
            self.assertEqual(SSRFTester().scan('http://example.com/?' + urlencode({'url': value})), [])
