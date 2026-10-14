from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit
import unittest
from unittest.mock import patch
from service import scan_target


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlsplit(self.path).query).get('q', [''])[0]
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(('<form><input name="q"></form>' + q).encode())

    def log_message(self, *args):
        pass


class TestIntegration(unittest.TestCase):
    @patch.dict('os.environ', {'NO_PROXY': '127.0.0.1,localhost'})
    def test_local_http_scan(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), DemoHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            report = scan_target(f'http://127.0.0.1:{server.server_port}/', ('xss', 'csrf'))
            self.assertEqual(report['summary']['total'], 3, report)
            self.assertTrue(report['summary']['complete'])
            self.assertEqual({v['type'] for v in report['vulnerabilities']}, {'XSS', 'CSRF'})
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
