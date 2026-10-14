class ReportGenerator:
    def generate(self, findings_list, errors=None):
        report = {'vulnerabilities': [], 'checks': [], 'errors': list(errors or [])}
        for findings in findings_list:
            for item in findings if isinstance(findings, list) else [findings]:
                if item.get('status') == 'info' or item.get('csrf_protected'):
                    report['checks'].append(dict(item))
                else:
                    report['vulnerabilities'].append(dict(item))
        report['summary'] = {'total': len(report['vulnerabilities']),
                             'complete': not report['errors']}
        return report
