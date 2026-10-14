from ipaddress import ip_address
from urllib.parse import parse_qs, urlsplit


class SSRFTester:
    def scan(self, url):
        findings = []
        for param, values in parse_qs(urlsplit(url).query).items():
            for value in values:
                try:
                    host = urlsplit(value if '://' in value else '//' + value).hostname
                    host = (host or '').lower().rstrip('.')
                    internal = host == 'localhost' or host.endswith('.localhost')
                    try:
                        address = ip_address(host)
                        internal = internal or address.is_private or address.is_loopback or address.is_link_local
                    except ValueError:
                        pass
                except ValueError:
                    continue
                if internal:
                    findings.append({
                        'type': 'SSRF', 'param': param, 'value': value,
                        'desc': 'Potential SSRF to internal resource; server-side request not verified.',
                        'risk': 'HIGH', 'status': 'potential',
                        'remediation': 'Allowlist destinations; validate resolved IPs and every redirect.',
                    })
        return findings
