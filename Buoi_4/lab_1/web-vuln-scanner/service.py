from urllib.parse import urlsplit
import requests
from scanners.csrf_detector import CSRFDetector
from scanners.sql_injection_tester import SQLInjectionTester
from scanners.ssrf_tester import SSRFTester
from scanners.xss_scanner import XSSScanner
from report.report_generator import ReportGenerator

OPTIONS = ('xss', 'sql', 'csrf', 'ssrf')


def scan_target(url, options=OPTIONS, html=None):
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
        raise ValueError('Nhập URL HTTP/HTTPS hợp lệ, không chứa thông tin đăng nhập.')
    if not options or any(option not in OPTIONS for option in options):
        raise ValueError('Chọn ít nhất một công cụ kiểm thử hợp lệ.')
    results, errors = [], []
    if 'xss' in options:
        scanner = XSSScanner()
        results.append(scanner.scan(url))
        errors.extend(scanner.errors)
    if 'sql' in options:
        results.append(SQLInjectionTester().scan(url))
    if 'ssrf' in options:
        results.append(SSRFTester().scan(url))
    if 'csrf' in options:
        try:
            if html is None:
                response = requests.get(url, timeout=5, allow_redirects=False)
                response.raise_for_status()
                if 300 <= response.status_code < 400:
                    raise requests.RequestException('Redirect not followed')
                html = response.text
            results.append(CSRFDetector().scan(html))
        except requests.RequestException as exc:
            errors.append(f'CSRF: {exc}')
    return ReportGenerator().generate(results, errors)
