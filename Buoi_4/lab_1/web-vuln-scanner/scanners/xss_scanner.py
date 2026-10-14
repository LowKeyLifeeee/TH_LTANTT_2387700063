from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import requests


class XSSScanner:
    def __init__(self):
        self.payloads = ['<script>alert(1)</script>', '\"><svg/onload=alert(1)>']
        self.errors = []

    def scan(self, url):
        self.errors = []
        findings = []
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        pairs = pairs or [('q', '')]
        for index, (param, _) in enumerate(pairs):
            for payload in self.payloads:
                query = pairs.copy()
                query[index] = (param, payload)
                test_url = urlunsplit(parts._replace(query=urlencode(query), fragment=''))
                try:
                    response = requests.get(test_url, timeout=5, allow_redirects=False)
                    response.raise_for_status()
                    if 300 <= response.status_code < 400:
                        self.errors.append(f'Redirect not followed: {test_url}')
                        continue
                    if payload in response.text:
                        findings.append({
                            'type': 'XSS', 'param': param, 'payload': payload, 'url': test_url,
                            'risk': 'HIGH', 'status': 'potential',
                            'desc': 'Payload reflected without encoding; browser execution not verified.',
                            'remediation': 'Apply context-aware output encoding and a Content Security Policy.',
                        })
                except requests.RequestException as exc:
                    self.errors.append(f'{test_url}: {exc}')
        return findings
