from html.parser import HTMLParser


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current = {'action': attrs.get('action', ''), 'token': False}
            self.forms.append(self.current)
        elif tag == 'input' and self.current is not None:
            if (attrs.get('name', '').lower() in
                    {'csrf_token', '_csrf', 'csrfmiddlewaretoken'}
                    and attrs.get('value', '').strip()):
                self.current['token'] = True

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


class CSRFDetector:
    def scan(self, html_content):
        parser = FormParser()
        parser.feed(html_content)
        missing = [i + 1 for i, form in enumerate(parser.forms) if not form['token']]
        return {
            'type': 'CSRF',
            'csrf_protected': bool(parser.forms) and not missing,
            'status': 'potential' if missing else 'info',
            'risk': 'MEDIUM' if missing else 'INFO',
            'param': ', '.join(f'form[{i}]' for i in missing),
            'desc': ('Potentially vulnerable to CSRF: form without a recognized token.'
                     if missing else 'Token present, or no forms found; server-side validation not verified.'),
            'remediation': 'Validate CSRF tokens server-side; use SameSite cookies and verify Origin.',
        }
