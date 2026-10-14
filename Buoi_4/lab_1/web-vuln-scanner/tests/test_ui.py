import unittest
from unittest.mock import patch, Mock
from ui.app import app


class TestUI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_index(self):
        self.assertEqual(self.client.get('/').status_code, 200)

    def test_bad_url(self):
        self.assertEqual(self.client.post('/', data={'url': 'file:///etc/passwd', 'scanner': 'xss'}).status_code, 400)

    def test_no_selection(self):
        self.assertEqual(self.client.post('/', data={'url': 'http://example.com/'}).status_code, 400)

    @patch('service.requests.get')
    def test_real_html_used_for_csrf(self, get):
        get.return_value = Mock(status_code=200, text='<form><input name="_csrf" value="abc"></form>')
        response = self.client.post('/', data={'url': 'http://example.com/', 'scanner': 'csrf'})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Token present', response.data)
        get.assert_called_once()

    @patch('ui.app.scan_target')
    def test_payload_is_escaped(self, scan):
        scan.return_value = {'summary': {'total': 1}, 'errors': [], 'checks': [], 'vulnerabilities': [
            {'type': 'XSS', 'risk': 'HIGH', 'payload': '<script>alert(1)</script>'}]}
        response = self.client.post('/', data={'url': 'http://example.com/', 'scanner': 'xss'})
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertNotIn(b'<script>alert', response.data)
