from urllib.parse import parse_qs, urlsplit


class SQLInjectionTester:
    # Static signatures from the lab. No SQL payload is sent to a server.
    payloads = ["' OR '1'='1", "'; DROP TABLE users;--", "' OR 1=1--",
                "' UNION SELECT NULL--"]

    def scan(self, url):
        findings = []
        for param, values in parse_qs(urlsplit(url).query).items():
            for value in values:
                for payload in self.payloads:
                    if payload.casefold() in value.casefold():
                        findings.append({
                            'type': 'SQL Injection', 'param': param, 'payload': payload,
                            'desc': 'Potential SQL Injection signature in URL; database behavior not tested.',
                            'risk': 'CRITICAL', 'status': 'potential',
                            'remediation': 'Use parameterized queries and least-privilege database accounts.',
                        })
        return findings
