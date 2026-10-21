import unittest
from unittest.mock import patch
import psutil
from app import app


class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_get_endpoints(self):
        for name, key in [('monitor', 'memory_usage'), ('memory', 'overflow_test'),
                          ('network', 'network_stats'), ('security', 'suspicious_calls')]:
            with self.subTest(endpoint=name):
                response = self.client.get('/api/'+name)
                self.assertEqual(response.status_code, 200)
                self.assertIn(key, response.get_json())

    def test_sandbox(self):
        response = self.client.post('/api/sandbox', json={'command': 'echo Hello Sandbox'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {'stdout': 'Hello Sandbox\n', 'stderr': ''})

    def test_invalid_requests(self):
        for body in ({}, [], {'command': 'whoami'}, {'command': 42}):
            self.assertEqual(self.client.post('/api/sandbox', json=body).status_code, 400)
        self.assertEqual(self.client.post('/api/sandbox', data='{', content_type='application/json').status_code, 400)
        self.assertEqual(self.client.get('/api/sandbox').status_code, 405)

    def test_access_denied(self):
        with patch('app.RuntimeMonitor', side_effect=psutil.AccessDenied(1)):
            self.assertEqual(self.client.get('/api/monitor').status_code, 503)
