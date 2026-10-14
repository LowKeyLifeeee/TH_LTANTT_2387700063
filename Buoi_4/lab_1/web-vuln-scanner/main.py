import argparse
import json
from pathlib import Path
from urllib.parse import urlencode
from service import scan_target, OPTIONS


def main():
    parser = argparse.ArgumentParser(description='WebVulnScanner - Lab 4.2')
    parser.add_argument('--url', help='URL của ứng dụng được phép kiểm thử')
    parser.add_argument('--scanners', nargs='+', choices=OPTIONS, default=list(OPTIONS))
    parser.add_argument('--output', help='Lưu báo cáo JSON')
    args = parser.parse_args()
    if args.url:
        try:
            report = scan_target(args.url, args.scanners)
        except ValueError as exc:
            parser.error(str(exc))
    else:
        # Offline demo, equivalent to the sample inputs in the handout.
        url = 'http://example.com/page?' + urlencode({
            'id': "' OR '1'='1", 'url': 'http://127.0.0.1/admin'})
        report = scan_target(url, ('sql', 'csrf', 'ssrf'),
                             '<form><input name="csrf_token" value="abc123"></form>')
    result = json.dumps(report, ensure_ascii=False, indent=2)
    print(result)
    if args.output:
        Path(args.output).write_text(result + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
